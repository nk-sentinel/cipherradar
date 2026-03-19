"""Pydantic schemas for git provider integration endpoints (ADR-014)."""

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic
from enum import StrEnum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ProviderType(StrEnum):
    """Supported git provider types."""

    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"


class CheckStatus(StrEnum):
    """Possible statuses for a commit check / build status."""

    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Shared value objects
# ---------------------------------------------------------------------------


class OAuthToken(BaseModel):
    """Token returned after completing the OAuth flow."""

    access_token: str
    token_type: str = "bearer"
    scope: str = ""
    refresh_token: str | None = None


class Repository(BaseModel):
    """Minimal representation of a remote repository."""

    id: str = Field(description="Provider-specific repository identifier")
    full_name: str = Field(description="owner/repo or namespace/project")
    clone_url: str
    default_branch: str = "main"


class Webhook(BaseModel):
    """Webhook registration result."""

    id: str
    url: str
    active: bool = True


# ---------------------------------------------------------------------------
# Integration management endpoints
# ---------------------------------------------------------------------------


class OAuthConnectRequest(BaseModel):
    """Initiate an OAuth connection by providing the authorisation code."""

    code: str = Field(min_length=1)


class OAuthConnectResponse(BaseModel):
    """Returned after a successful OAuth exchange."""

    provider: ProviderType
    connected: bool = True
    repositories_available: int = 0


class IntegrationResponse(BaseModel):
    """A single connected integration."""

    id: uuid.UUID
    provider: ProviderType
    account_name: str
    connected_at: datetime


class IntegrationListResponse(BaseModel):
    """List of connected integrations."""

    items: list[IntegrationResponse]
    total: int


# ---------------------------------------------------------------------------
# Webhook payloads (incoming)
# ---------------------------------------------------------------------------


class WebhookScanTrigger(BaseModel):
    """Internal representation of a webhook event that should trigger a scan."""

    provider: ProviderType
    repo_full_name: str
    branch: str
    commit_sha: str
    event_type: str = "push"
