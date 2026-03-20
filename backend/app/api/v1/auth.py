"""Auth API endpoints (ADR-013).

Handles login, token refresh, API key management, and user info.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
import bcrypt as _bcrypt_lib

from app.auth.jwt import JWTError, create_access_token, create_refresh_token, decode_token
from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import API_KEY_CREATOR_ROLES, ROLE_DEFAULT_SCOPES, Role
from app.config import settings
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyResponse,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserInfo,
)

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


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest) -> TokenResponse:
    """Authenticate with email + password and receive JWT tokens."""
    if _user_by_email is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Auth backend not configured")

    user = await _user_by_email(body.email)
    if user is None or not _bcrypt_lib.checkpw(body.password.encode(), user["hashed_password"].encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is deactivated")

    role = user["role"]
    role_enum = Role(role) if role in Role.__members__.values() else Role.DEVELOPER
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role_enum, [])]

    access_token = create_access_token(user_id=str(user["id"]), role=role, scopes=scopes)
    refresh_token = create_refresh_token(user_id=str(user["id"]))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/refresh
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest) -> TokenResponse:
    """Exchange a valid refresh token for a new access + refresh token pair."""
    try:
        payload = decode_token(body.refresh_token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        ) from exc

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload["sub"]

    # Re-fetch user to pick up any role changes since the original login.
    if _user_by_email is not None:
        # For refresh we only have user_id, not email.  A production
        # implementation would look up by ID.  For now, issue tokens with the
        # role from the original refresh payload or a default.
        pass

    # Issue fresh tokens with the same identity.
    # In production the role/scopes would be re-read from the database.
    role = payload.get("role", "developer")
    role_enum = Role(role) if role in Role.__members__.values() else Role.DEVELOPER
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role_enum, [])]

    access_token = create_access_token(user_id=user_id, role=role, scopes=scopes)
    new_refresh = create_refresh_token(user_id=user_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


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
