"""Schemas for finding request operations (D15 — FP/RA request workflow)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.schemas.base import CamelCaseModel


class RequestType(StrEnum):
    """Types of finding requests."""

    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"


class RequestStatus(StrEnum):
    """Status values for finding requests."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class FindingRequestCreate(CamelCaseModel):
    """Request body for creating a FP/RA request."""

    request_type: RequestType
    justification: str = Field(min_length=1, max_length=5000)


class FindingRequestResponse(CamelCaseModel):
    """Response for a single finding request."""

    id: uuid.UUID
    finding_id: uuid.UUID
    requested_by: uuid.UUID | None = None
    reviewed_by: uuid.UUID | None = None
    request_type: str
    status: str
    justification: str
    review_note: str | None = None
    expires_at: datetime | None = None
    reviewed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class FindingRequestListResponse(CamelCaseModel):
    """Paginated list of finding requests."""

    items: list[FindingRequestResponse]
    total: int
    page: int
    per_page: int = Field(default=25)


class FindingRequestReject(CamelCaseModel):
    """Request body for rejecting a request."""

    reason: str = Field(min_length=1, max_length=5000)
