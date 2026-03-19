"""JWT token creation and verification (ADR-013).

Access tokens carry user identity, role, and scopes.  Refresh tokens
carry only the user ID and are used to obtain new access tokens.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt

from app.config import settings

# Re-export JWTError so callers don't need to import jose directly.
__all__ = ["JWTError", "create_access_token", "create_refresh_token", "decode_token"]


def create_access_token(
    user_id: str,
    role: str,
    scopes: list[str],
    *,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a short-lived JWT access token.

    Args:
        user_id: UUID of the authenticated user (stored as ``sub``).
        role: Active role string (e.g. ``"org_admin"``).
        scopes: Permission scopes granted for this session.
        expires_delta: Override the default 15-minute expiry.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes))
    payload: dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "scopes": scopes,
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    user_id: str,
    *,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a long-lived refresh token.

    Args:
        user_id: UUID of the authenticated user (stored as ``sub``).
        expires_delta: Override the default 7-day expiry.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(days=settings.jwt_refresh_token_expire_days))
    payload: dict[str, Any] = {
        "sub": user_id,
        "type": "refresh",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token.

    Args:
        token: Encoded JWT string.

    Returns:
        Decoded payload dictionary.

    Raises:
        jose.JWTError: If the token is invalid, expired, or tampered with.
    """
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
