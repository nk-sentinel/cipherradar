from pydantic import Field

from app.schemas.base import CamelCaseModel


class PolicyRule(CamelCaseModel):
    """A single policy rule with its current state and violation count."""

    id: str = Field(description="Rule identifier (e.g. no-broken-algorithms)")
    name: str
    description: str
    severity: str = Field(description="critical, high, medium, low")
    enabled: bool = True
    violation_count: int = Field(default=0, ge=0)


class PolicyRuleListResponse(CamelCaseModel):
    """List of all policy rules."""

    rules: list[PolicyRule]
    total: int


class PolicyRuleToggle(CamelCaseModel):
    """Request schema for toggling a policy rule."""

    enabled: bool
