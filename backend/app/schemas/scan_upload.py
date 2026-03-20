import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import BaseModel, Field


class ScanUploadRequest(BaseModel):
    """Request schema for uploading scan results via CycloneDX JSON."""

    project_name: str = Field(min_length=1, max_length=255)
    group_path: str | None = Field(default=None, max_length=1024)
    branch: str | None = Field(default=None, max_length=255)
    commit_sha: str | None = Field(default=None, max_length=40)


class ScanUploadResponse(BaseModel):
    """Response after a successful scan upload."""

    scan_id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    group_path: str | None = None
    findings_count: int = Field(ge=0)
    status: str
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime
