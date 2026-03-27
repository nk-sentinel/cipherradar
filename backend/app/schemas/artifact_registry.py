"""Schemas for artifact registry CRUD (D2)."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import Field

from app.schemas.base import CamelCaseModel


class RegistryCreate(CamelCaseModel):
    """Request schema for creating an artifact registry."""

    name: str = Field(min_length=1, max_length=255)
    registry_type: str = Field(
        description="Registry type: jfrog, ecr, gcr, acr, docker_hub, harbor, gitlab, custom"
    )
    url: str = Field(min_length=1, max_length=512)
    auth_token_encrypted: str | None = None
    enabled: bool = True


class RegistryUpdate(CamelCaseModel):
    """Request schema for updating an artifact registry."""

    name: str | None = None
    registry_type: str | None = None
    url: str | None = None
    auth_token_encrypted: str | None = None
    enabled: bool | None = None


class RegistryResponse(CamelCaseModel):
    """Response schema for an artifact registry."""

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    registry_type: str
    url: str
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class RegistryTestResult(CamelCaseModel):
    """Result of a registry connection test."""

    success: bool
    message: str
    latency_ms: float | None = None
