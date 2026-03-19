from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    """Request schema for creating a new scan."""

    project_id: uuid.UUID
    branch: str | None = None
    commit_sha: str | None = None
    passes: list[int] = Field(default=[1], description="Detection passes to run (1=tree-sitter, 2=OpenGrep, 3=Joern)")


class ScanResponse(BaseModel):
    """Response schema for a single scan."""

    id: uuid.UUID
    project_id: uuid.UUID
    status: str
    branch: str | None
    commit_sha: str | None
    findings_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: list[ScanResponse]
    total: int
    page: int
    per_page: int


class CBOMResponse(BaseModel):
    """Response schema for a scan's CBOM document."""

    scan_id: uuid.UUID
    spec_version: str
    serial_number: str | None
    components_count: int
    cbom_json: dict
