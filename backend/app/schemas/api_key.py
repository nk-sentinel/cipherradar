"""Pydantic request/response models for API key management endpoints (D7)."""

from __future__ import annotations

import uuid  # noqa: TC003 — Pydantic needs runtime access with deferred annotations
from datetime import datetime  # noqa: TC003

from pydantic import Field

from app.schemas.base import CamelCaseModel


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class ApiKeyCreateRequest(CamelCaseModel):
    """Request body when creating a new API key."""

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str]
    expires_in_days: int | None = Field(
        default=None, description="Optional expiration in days from creation"
    )


class ApiKeyCreateResponse(CamelCaseModel):
    """API key creation response. ``key`` is shown once only."""

    id: uuid.UUID
    name: str
    key: str = Field(description="Plaintext key — shown once at creation only")
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None = None


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class ApiKeyListItem(CamelCaseModel):
    """API key summary for listing (no plaintext key)."""

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiKeyListResponse(CamelCaseModel):
    """Response for listing API keys."""

    items: list[ApiKeyListItem]
    total: int


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------


class ApiKeyRevokeResponse(CamelCaseModel):
    """Response after revoking an API key."""

    message: str = "API key revoked successfully"
