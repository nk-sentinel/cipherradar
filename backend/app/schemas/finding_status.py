"""Schemas for finding status operations (D14, D17)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.schemas.base import CamelCaseModel


class FindingStatus(StrEnum):
    """Allowed finding statuses (D14)."""

    OPEN = "open"
    IN_REVIEW = "in_review"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class ReasonCategory(StrEnum):
    """Reason categories for risk acceptance (D14)."""

    COMPENSATING_CONTROL = "compensating_control"
    LOW_IMPACT = "low_impact"
    MIGRATION_PLANNED = "migration_planned"
    BUSINESS_EXCEPTION = "business_exception"


class FindingStatusUpdate(CamelCaseModel):
    """Request body for changing a finding's status."""

    status: FindingStatus
    reason: str | None = None
    reason_category: ReasonCategory | None = None
    review_date: datetime | None = None


class FindingStatusResponse(CamelCaseModel):
    """Response after a finding status change."""

    id: uuid.UUID
    status: str
    assigned_to: uuid.UUID | None = None
    updated_at: datetime

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class FindingStatusHistoryItem(CamelCaseModel):
    """Single entry in a finding's status history."""

    id: uuid.UUID
    old_status: str | None = None
    new_status: str
    changed_by: uuid.UUID | None = None
    reason: str | None = None
    created_at: datetime

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class FindingAssignment(CamelCaseModel):
    """Request body for assigning a finding to a user."""

    assignee_id: uuid.UUID


class FindingStatusHistoryResponse(CamelCaseModel):
    """Paginated status history response."""

    items: list[FindingStatusHistoryItem]
    total: int
    page: int
    per_page: int = Field(default=25)
