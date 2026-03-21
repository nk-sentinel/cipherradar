"""Pydantic request/response models for the auth endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from app.schemas.base import CamelCaseModel

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class LoginRequest(CamelCaseModel):
    """Email + password login payload."""

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1)


class TokenResponse(CamelCaseModel):
    """JWT access + refresh token pair returned on login and refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds")


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------


class RefreshRequest(CamelCaseModel):
    """Payload for token refresh."""

    refresh_token: str


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


class ApiKeyCreate(CamelCaseModel):
    """Request body when creating a new API key."""

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str]


class ApiKeyResponse(CamelCaseModel):
    """API key details.  ``key`` is populated only on creation."""

    id: uuid.UUID
    name: str
    key: str | None = Field(default=None, description="Plaintext key — shown once at creation only")
    scopes: list[str]
    created_at: datetime


# ---------------------------------------------------------------------------
# User info
# ---------------------------------------------------------------------------


class UserInfo(CamelCaseModel):
    """Current user info returned by ``/me``."""

    user_id: str
    role: str
    scopes: list[str]
    auth_method: str
