"""Schemas for policy cascade endpoints (D26)."""

from __future__ import annotations

from pydantic import Field

from app.schemas.base import CamelCaseModel


class PolicyRuleEffective(CamelCaseModel):
    """An effective policy rule after cascade resolution."""

    id: str
    severity: str
    enabled: bool = True
    action: str = "warn"
    reason: str | None = None
    override_id: str | None = None


class PolicyCascadeResponse(CamelCaseModel):
    """Response showing effective policy with cascade info."""

    rules: list[PolicyRuleEffective]
    locked_rules: list[str] = Field(default_factory=list)
    scope: str  # "org", "group", or "project"


class PolicyOverrideRequest(CamelCaseModel):
    """Request to create/update a policy override."""

    rule_id: str
    action: str = Field(..., description="Action: fail, warn, ignore, lock")
    reason: str | None = None


class PolicyOverrideResponse(CamelCaseModel):
    """Response after saving a policy override."""

    rule_id: str
    action: str
    saved: bool
