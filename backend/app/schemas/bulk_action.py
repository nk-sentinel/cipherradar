"""Schemas for bulk action operations (D19)."""

from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import Field

from app.schemas.base import CamelCaseModel


class BulkAction(StrEnum):
    """Supported bulk actions (D19)."""

    ASSIGN = "assign"
    STATUS_CHANGE = "status_change"
    MARK_FP = "mark_fp"
    MARK_RA = "mark_ra"
    RAISE_FP_REQUEST = "raise_fp_request"
    RAISE_RA_REQUEST = "raise_ra_request"
    EXPORT = "export"


class BulkActionRequest(CamelCaseModel):
    """Request body for bulk finding actions."""

    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    action: BulkAction
    params: dict = Field(default_factory=dict)


class BulkActionResultItem(CamelCaseModel):
    """Result for a single finding in a bulk operation."""

    finding_id: uuid.UUID
    success: bool
    error: str | None = None


class BulkActionResponse(CamelCaseModel):
    """Response for a bulk action."""

    total: int
    succeeded: int
    failed: int
    results: list[BulkActionResultItem]
