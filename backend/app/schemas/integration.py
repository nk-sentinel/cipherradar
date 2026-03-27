"""Schemas for integration management endpoints (D3)."""

from __future__ import annotations

import uuid

from pydantic import Field

from app.schemas.base import CamelCaseModel


class IntegrationConnectRequest(CamelCaseModel):
    """Request body to connect a git provider via PAT."""

    token: str = Field(..., description="Personal Access Token for the provider")


class IntegrationConnectResponse(CamelCaseModel):
    """Response after connecting a provider."""

    id: str
    provider: str
    status: str = "connected"
    connected_at: str


class IntegrationStatusResponse(CamelCaseModel):
    """Response after disconnecting a provider."""

    provider: str
    status: str


class IntegrationTestResponse(CamelCaseModel):
    """Response from testing a provider connection."""

    ok: bool
    provider: str | None = None
    error: str | None = None


class DiscoveredRepo(CamelCaseModel):
    """A repository discovered from a connected provider."""

    name: str
    url: str
    default_branch: str = "main"


class DiscoverReposResponse(CamelCaseModel):
    """Response listing discovered repositories."""

    repos: list[DiscoveredRepo]
    total: int


class ImportReposRequest(CamelCaseModel):
    """Request to import discovered repos as projects."""

    repos: list[DiscoveredRepo] = Field(..., min_length=1)
    group_id: uuid.UUID = Field(..., description="Target group for imported projects")
    provider: str


class ImportReposResponse(CamelCaseModel):
    """Response after importing repos."""

    imported: int
    provider: str
