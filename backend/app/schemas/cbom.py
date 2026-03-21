import enum
import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import Field

from app.schemas.base import CamelCaseModel


class ChangeType(enum.StrEnum):
    """Type of change detected in a CBOM diff."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class CBOMVersion(CamelCaseModel):
    """A single CBOM snapshot version for a project."""

    scan_id: uuid.UUID
    version_number: int
    created_at: datetime
    findings_count: int
    spec_version: str


class CBOMDiffItem(CamelCaseModel):
    """A single component change between two CBOM documents."""

    name: str
    file: str
    line: int
    change_type: ChangeType
    details: str | None = None


class CBOMDiff(CamelCaseModel):
    """Result of comparing two CBOM documents."""

    base_scan_id: uuid.UUID
    head_scan_id: uuid.UUID
    added: list[CBOMDiffItem]
    removed: list[CBOMDiffItem]
    changed: list[CBOMDiffItem]
    unchanged_count: int


class MergedCBOM(CamelCaseModel):
    """Aggregated CBOM from multiple scans."""

    project_ids: list[uuid.UUID]
    total_components: int
    components: list[dict]


class MergeRequest(CamelCaseModel):
    """Request body for merging multiple CBOMs."""

    scan_ids: list[uuid.UUID] = Field(..., min_length=1, description="Scan IDs to merge")
