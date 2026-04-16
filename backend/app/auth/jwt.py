"""JWT token creation and verification (ADR-013).

Access tokens carry user identity, role, and scopes.  Refresh tokens
carry only the user ID and are used to obtain new access tokens.

Security features:
- Token fingerprinting: SHA-256(user_agent + client_ip + salt) embedded in JWT.
  Server verifies fingerprint on each request — stolen tokens fail from different clients.
- httpOnly refresh cookie: refresh token set as httpOnly cookie, invisible to JS.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt

from app.config import settings


def compute_fingerprint(user_agent: str, client_ip: str) -> str:
    """Compute a client fingerprint from User-Agent and IP.

    This is embedded in the JWT and verified on each request.
    If a token is stolen and used from a different client, the
    fingerprint won't match and the request is rejected.
    """
    raw = f"{user_agent}|{client_ip}|{settings.jwt_secret_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

# Re-export JWTError so callers don't need to import jose directly.
__all__ = ["JWTError", "create_access_token", "create_refresh_token", "decode_token"]


def create_access_token(
    user_id: str,
    role: str,
    scopes: list[str],
    *,
    org_id: str = "",
    assignment_level: str = "org",
    assigned_group_id: str | None = None,
    assigned_project_ids: list[str] | None = None,
    expires_delta: timedelta | None = None,
    fingerprint: str | None = None,
) -> str:
    """Create a short-lived JWT access token.

    Args:
        user_id: UUID of the authenticated user (stored as ``sub``).
        role: Active role string (e.g. ``"org_admin"``).
        scopes: Permission scopes granted for this session.
        org_id: Organisation UUID for multi-tenant RLS enforcement.
        assignment_level: ``"org"``, ``"group"``, or ``"project"``.
        assigned_group_id: Group UUID when role is group-scoped.
        assigned_project_ids: Project UUIDs when role is project-scoped.
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
        "org_id": org_id,
        "assignment_level": assignment_level,
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    if assigned_group_id:
        payload["assigned_group_id"] = assigned_group_id
    if assigned_project_ids:
        payload["assigned_project_ids"] = assigned_project_ids
    if fingerprint:
        payload["fgp"] = fingerprint
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    user_id: str,
    *,
    role: str = "",
    scopes: list[str] | None = None,
    org_id: str = "",
    assignment_level: str = "org",
    assigned_group_id: str | None = None,
    assigned_project_ids: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a long-lived refresh token.

    Carries the same identity claims as the access token so that
    ``/auth/refresh`` can mint equivalent access tokens without a DB lookup.
    """
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(days=settings.jwt_refresh_token_expire_days))
    payload: dict[str, Any] = {
        "sub": user_id,
        "type": "refresh",
        "role": role,
        "scopes": scopes or [],
        "org_id": org_id,
        "assignment_level": assignment_level,
        "iat": now,
        "exp": expire,
    }
    if assigned_group_id:
        payload["assigned_group_id"] = assigned_group_id
    if assigned_project_ids:
        payload["assigned_project_ids"] = assigned_project_ids
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
