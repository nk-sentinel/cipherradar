"""Pydantic request/response models for the auth endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Email + password login payload."""

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    """JWT access + refresh token pair returned on login and refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds")


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------


class RefreshRequest(BaseModel):
    """Payload for token refresh."""

    refresh_token: str


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


class ApiKeyCreate(BaseModel):
    """Request body when creating a new API key."""

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str]


class ApiKeyResponse(BaseModel):
    """API key details.  ``key`` is populated only on creation."""

    id: uuid.UUID
    name: str
    key: str | None = Field(default=None, description="Plaintext key — shown once at creation only")
    scopes: list[str]
    created_at: datetime


# ---------------------------------------------------------------------------
# User info
# ---------------------------------------------------------------------------


class UserInfo(BaseModel):
    """Current user info returned by ``/me``."""

    user_id: str
    role: str
    scopes: list[str]
    auth_method: str
