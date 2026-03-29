"""Auth API endpoints (ADR-013).

Handles login, token refresh, API key management, and user info.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

import bcrypt as _bcrypt_lib
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.auth.jwt import JWTError, compute_fingerprint, create_access_token, create_refresh_token, decode_token
from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import API_KEY_CREATOR_ROLES, ROLE_DEFAULT_SCOPES, Role
from app.config import settings
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyResponse,
    LoginRequest,
    RecoverRequest,
    RecoverResponse,
    RefreshRequest,
    UserInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Pluggable backend look-ups.
#
# These are thin async callables that the real DB layer will replace.  Tests
# can monkeypatch them without touching the database at all.
# ---------------------------------------------------------------------------
_user_by_email = None  # async (email) -> dict | None  {id, email, hashed_password, role, is_active}
_store_api_key = None  # async (record: dict) -> None


def set_user_lookup(fn):  # noqa: ANN001, ANN201
    """Register async callback ``(email: str) -> dict | None`` for user lookup."""
    global _user_by_email  # noqa: PLW0603
    _user_by_email = fn


def set_api_key_store(fn):  # noqa: ANN001, ANN201
    """Register async callback ``(record: dict) -> None`` for persisting an API key."""
    global _store_api_key  # noqa: PLW0603
    _store_api_key = fn


# ---------------------------------------------------------------------------
# POST /api/v1/auth/login
# ---------------------------------------------------------------------------


@router.post("/login")
async def login(body: LoginRequest, request: Request) -> Response:
    """Authenticate with email + password and receive JWT tokens.

    Sets refresh token as httpOnly cookie for security.
    Access token returned in response body.
    """
    if _user_by_email is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Auth backend not configured")

    user = await _user_by_email(body.email)
    if user is None or not _bcrypt_lib.checkpw(body.password.encode(), user["hashed_password"].encode()):
        logger.warning(
            "Login failed",
            extra={"extra_fields": {"email": body.email, "reason": "invalid_credentials"}},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.get("is_active", True):
        logger.warning(
            "Login failed",
            extra={"extra_fields": {
                "email": body.email,
                "user_id": str(user["id"]),
                "reason": "account_deactivated",
            }},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is deactivated")

    role = user["role"]
    role_enum = Role(role) if role in Role.__members__.values() else Role.DEVELOPER
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role_enum, [])]

    # Compute client fingerprint for token binding
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    fgp = compute_fingerprint(user_agent, client_ip)

    access_token = create_access_token(
        user_id=str(user["id"]),
        role=role,
        scopes=scopes,
        org_id=user.get("org_id", ""),
        fingerprint=fgp,
    )
    refresh_token = create_refresh_token(user_id=str(user["id"]))

    logger.info(
        "Login successful",
        extra={"extra_fields": {
            "user_id": str(user["id"]),
            "email": body.email,
            "role": role,
            "org_id": user.get("org_id", ""),
        }},
    )

    # Return access token in body, set refresh token as httpOnly cookie
    response = JSONResponse(content={
        "accessToken": access_token,
        "tokenType": "bearer",
        "expiresIn": settings.jwt_access_token_expire_minutes * 60,
    })
    response.set_cookie(
        key="cipherradar_refresh",
        value=refresh_token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/api/v1/auth/refresh",
        max_age=settings.jwt_refresh_token_expire_days * 86400,
    )
    return response


# ---------------------------------------------------------------------------
# POST /api/v1/auth/refresh
# ---------------------------------------------------------------------------


@router.post("/refresh")
async def refresh(request: Request, body: RefreshRequest | None = None) -> Response:
    """Exchange a valid refresh token for a new access + refresh token pair.

    Reads refresh token from httpOnly cookie (preferred) or request body (legacy).
    Sets new refresh token as httpOnly cookie.
    """
    # Read refresh token: prefer httpOnly cookie, fall back to body
    refresh_token = request.cookies.get("cipherradar_refresh")
    if not refresh_token and body and body.refresh_token:
        refresh_token = body.refresh_token
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token provided")

    try:
        payload = decode_token(refresh_token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        ) from exc

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload["sub"]

    # Re-read role from DB if possible, otherwise use stored role
    role = payload.get("role", "developer")
    role_enum = Role(role) if role in Role.__members__.values() else Role.DEVELOPER
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role_enum, [])]

    # Compute fingerprint for new access token
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    fgp = compute_fingerprint(user_agent, client_ip)

    access_token = create_access_token(
        user_id=user_id, role=role, scopes=scopes,
        org_id=payload.get("org_id", ""),
        fingerprint=fgp,
    )
    new_refresh = create_refresh_token(user_id=user_id)

    logger.info("Token refreshed", extra={"extra_fields": {"user_id": user_id}})

    response = JSONResponse(content={
        "accessToken": access_token,
        "tokenType": "bearer",
        "expiresIn": settings.jwt_access_token_expire_minutes * 60,
    })
    response.set_cookie(
        key="cipherradar_refresh",
        value=new_refresh,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/api/v1/auth/refresh",
        max_age=settings.jwt_refresh_token_expire_days * 86400,
    )
    return response


# ---------------------------------------------------------------------------
# POST /api/v1/auth/logout
# ---------------------------------------------------------------------------


@router.post("/logout")
async def logout() -> Response:
    """Clear the refresh token cookie."""
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(
        key="cipherradar_refresh",
        path="/api/v1/auth/refresh",
    )
    logger.info("User logged out")
    return response


# ---------------------------------------------------------------------------
# POST /api/v1/auth/api-keys
# ---------------------------------------------------------------------------


@router.post("/api-keys", response_model=ApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreate,
    user: AuthenticatedUser = Depends(require_role(*API_KEY_CREATOR_ROLES)),
) -> ApiKeyResponse:
    """Create a scoped API key (Org Admin / Security Manager / Security Engineer only)."""
    from app.auth.api_keys import generate_api_key

    plaintext_key, key_hash = generate_api_key()
    key_id = uuid.uuid4()
    now = datetime.now(UTC)

    record = {
        "id": key_id,
        "name": body.name,
        "hash": key_hash,
        "scopes": body.scopes,
        "created_by": user.user_id,
        "created_at": now,
    }

    if _store_api_key is not None:
        await _store_api_key(record)

    return ApiKeyResponse(
        id=key_id,
        name=body.name,
        key=plaintext_key,
        scopes=body.scopes,
        created_at=now,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/me
# ---------------------------------------------------------------------------


@router.get("/me", response_model=UserInfo)
async def me(user: AuthenticatedUser = Depends(get_current_user)) -> UserInfo:
    """Return identity info for the currently authenticated user."""
    return UserInfo(
        user_id=user.user_id,
        role=user.role,
        scopes=user.scopes,
        auth_method=user.auth_method,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/recover — break-glass recovery (D9)
# ---------------------------------------------------------------------------

# Recovery key — in production, this would be stored securely (e.g. HSM, vault).
# It is set during initial deployment and rotated after each use.
_recovery_key = None  # str | None


def set_recovery_key(key: str | None) -> None:  # noqa: ANN001
    """Set the break-glass recovery key. Called during deployment or testing."""
    global _recovery_key  # noqa: PLW0603
    _recovery_key = key


@router.post("/recover", response_model=RecoverResponse)
async def recover(body: RecoverRequest) -> RecoverResponse:
    """Break-glass recovery: reset an Org Admin's password using a recovery key.

    This endpoint is for emergency use when the last OA is locked out.
    The recovery key is invalidated after use.
    """
    global _recovery_key  # noqa: PLW0603
    import hmac

    if _recovery_key is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Recovery is not configured",
        )

    if not hmac.compare_digest(body.recovery_key, _recovery_key):
        logger.warning(
            "Recovery attempt failed",
            extra={"extra_fields": {"email": body.email, "reason": "invalid_recovery_key"}},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid recovery key",
        )

    if _user_by_email is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth backend not configured",
        )

    user = await _user_by_email(body.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Hash new password and update (via the pluggable backend)
    new_hash = _bcrypt_lib.hashpw(body.new_password.encode(), _bcrypt_lib.gensalt()).decode()

    # Store the new hash — this uses a separate callback for recovery
    if _store_recovery_password is not None:
        await _store_recovery_password(body.email, new_hash)

    # Invalidate recovery key after use
    _recovery_key = None

    logger.warning(
        "Break-glass recovery used",
        extra={"extra_fields": {"email": body.email, "user_id": str(user["id"])}},
    )

    return RecoverResponse()


# Pluggable callback for recovery password storage
_store_recovery_password = None  # async (email: str, hashed_password: str) -> None


def set_recovery_password_store(fn) -> None:  # noqa: ANN001, ANN201
    """Register async callback for storing a recovery password reset."""
    global _store_recovery_password  # noqa: PLW0603
    _store_recovery_password = fn
