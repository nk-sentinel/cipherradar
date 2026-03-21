"""Pydantic schemas for the LLM-assisted remediation API."""

import uuid

from pydantic import Field

from app.schemas.base import CamelCaseModel


class RemediationRequest(CamelCaseModel):
    """Request body to generate an LLM remediation for a finding."""

    consent: bool = Field(
        ...,
        description=(
            "Explicit opt-in consent that code snippets will be sent to an LLM provider. "
            "Must be true to proceed."
        ),
    )


class RemediationBatchRequest(CamelCaseModel):
    """Request body to batch-remediate multiple findings."""

    finding_ids: list[uuid.UUID] = Field(
        ...,
        description="List of finding UUIDs to remediate.",
        min_length=1,
        max_length=50,
    )
    consent: bool = Field(
        ...,
        description="Explicit opt-in consent for sending code to an LLM provider.",
    )


class RemediationResponse(CamelCaseModel):
    """Response containing an LLM-generated remediation suggestion."""

    finding_id: uuid.UUID
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    provider: str
    cached: bool = False


class RemediationBatchResponse(CamelCaseModel):
    """Response for batch remediation — one result per finding."""

    items: list[RemediationResponse]
    total: int
