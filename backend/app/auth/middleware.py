"""FastAPI authentication dependencies (ADR-013).

Provides dependency functions for extracting the current user from a
JWT Bearer token or API key, and for enforcing role / scope checks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.api_keys import verify_api_key
from app.auth.jwt import JWTError, decode_token

if TYPE_CHECKING:
    from app.auth.roles import Role

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Lightweight user-info carrier returned by the auth dependencies
# ---------------------------------------------------------------------------


class AuthenticatedUser:
    """Minimal identity object extracted from a JWT or API key."""

    __slots__ = ("user_id", "role", "scopes", "auth_method")

    def __init__(
        self,
        user_id: str,
        role: str,
        scopes: list[str],
        *,
        auth_method: str = "jwt",
    ) -> None:
        self.user_id = user_id
        self.role = role
        self.scopes = scopes
        self.auth_method = auth_method


# ---------------------------------------------------------------------------
# Core dependency: extract user from JWT Bearer token
# ---------------------------------------------------------------------------


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    """Extract and validate the current user from a JWT Bearer token.

    Raises:
        HTTPException 401: If the token is missing, invalid, or expired.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return AuthenticatedUser(
        user_id=payload["sub"],
        role=payload.get("role", ""),
        scopes=payload.get("scopes", []),
    )


# ---------------------------------------------------------------------------
# Extended dependency: accept either JWT or API key
# ---------------------------------------------------------------------------

# In-memory stub for API key lookup.  The real implementation will query the
# database.  Tests can monkeypatch this callable.
_api_key_lookup: Any = None


def set_api_key_lookup(fn: Any) -> None:  # noqa: ANN401
    """Register the callback used by ``get_current_user_or_api_key`` to look
    up an API key record from the database.

    The callback signature must be ``async def(key: str) -> dict | None``
    where the returned dict has keys ``hash``, ``user_id``, ``role``,
    ``scopes``.
    """
    global _api_key_lookup  # noqa: PLW0603
    _api_key_lookup = fn


async def get_current_user_or_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    """Authenticate via JWT Bearer token *or* API key.

    The function first attempts JWT validation.  If no ``Bearer`` token is
    present, it checks the ``Authorization`` header for a raw API key
    (prefixed ``cbom_sk_``).

    Raises:
        HTTPException 401: If neither authentication method succeeds.
    """
    # 1) Try JWT first
    if credentials is not None:
        try:
            return await get_current_user(credentials)
        except HTTPException:
            pass  # fall through to API key check

    # 2) Try API key from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("cbom_sk_"):
        api_key = auth_header
    elif auth_header.lower().startswith("bearer cbom_sk_"):
        api_key = auth_header.split(" ", 1)[1]
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if _api_key_lookup is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key authentication not configured",
        )

    record = await _api_key_lookup(api_key)
    if record is None or not verify_api_key(api_key, record["hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return AuthenticatedUser(
        user_id=record["user_id"],
        role=record.get("role", ""),
        scopes=record.get("scopes", []),
        auth_method="api_key",
    )


# ---------------------------------------------------------------------------
# Role / scope guard dependencies
# ---------------------------------------------------------------------------


def require_role(*roles: str | Role):
    """Return a FastAPI dependency that rejects users without one of *roles*.

    Usage::

        @router.get("/admin", dependencies=[Depends(require_role(Role.ORG_ADMIN))])
        async def admin_only(): ...
    """
    allowed = {str(r) for r in roles}

    async def _check(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return _check


def require_scope(*scopes: str):
    """Return a FastAPI dependency that rejects tokens missing any of *scopes*.

    Usage::

        @router.get("/scans", dependencies=[Depends(require_scope("scan:read"))])
        async def list_scans(): ...
    """
    required = set(scopes)

    async def _check(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not required.issubset(set(user.scopes)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient scope",
            )
        return user

    return _check
