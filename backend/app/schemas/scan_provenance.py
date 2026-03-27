"""Schemas for scan provenance and environment promotion (D21)."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import Field

from app.schemas.base import CamelCaseModel


class ProvenanceResponse(CamelCaseModel):
    """Scan provenance information including artifact and environment data."""

    scan_id: uuid.UUID
    project_id: uuid.UUID
    branch: str | None = None
    commit_sha: str | None = None
    tag: str | None = None
    image_ref: str | None = None
    image_digest: str | None = None
    artifact_filename: str | None = None
    artifact_checksum: str | None = None
    environment: str | None = None
    promoted_at: datetime | None = None
    promoted_by: uuid.UUID | None = None
    created_at: datetime

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class PromoteRequest(CamelCaseModel):
    """Request to promote a scan from one environment to another."""

    scan_id: uuid.UUID
    from_env: str = Field(description="Source environment name")
    to_env: str = Field(description="Target environment name")


class EnvironmentStageResponse(CamelCaseModel):
    """A configured environment stage."""

    id: uuid.UUID
    name: str
    display_order: int
    color: str | None = None
    is_production: bool = False

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class EnvironmentStageCreate(CamelCaseModel):
    """Create/update an environment stage."""

    name: str
    display_order: int = 0
    color: str | None = None
    is_production: bool = False
