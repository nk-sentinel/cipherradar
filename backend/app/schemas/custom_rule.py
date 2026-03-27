"""Schemas for custom rule management endpoints (D27)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.schemas.base import CamelCaseModel


class CustomRuleCreateRequest(CamelCaseModel):
    """Request body to upload a custom rule."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    language: str = Field(..., description="Target language (e.g. python, java)")
    pattern_type: str = Field(default="opengrep", description="opengrep or regex")
    pattern: str = Field(..., description="Rule pattern (YAML for OpenGrep)")
    severity: str = Field(default="medium", description="critical, high, medium, low")


class CustomRuleUpdateRequest(CamelCaseModel):
    """Request body to update a custom rule."""

    name: str | None = None
    description: str | None = None
    pattern: str | None = None
    severity: str | None = None
    enabled: bool | None = None


class CustomRuleResponse(CamelCaseModel):
    """Response representing a custom rule."""

    id: str
    name: str
    description: str | None = None
    language: str
    pattern_type: str
    pattern: str
    severity: str
    enabled: bool = True
    created_by: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    parent_rule: str | None = None


class CustomRuleListResponse(CamelCaseModel):
    """Response listing custom rules."""

    items: list[CustomRuleResponse]
    total: int


class CustomRuleForkRequest(CamelCaseModel):
    """Request to fork a built-in rule."""

    builtin_id: str = Field(..., description="ID of the built-in rule to fork")


class CustomRuleDryRunRequest(CamelCaseModel):
    """Request to test a custom rule against sample code."""

    test_code: str = Field(..., description="Code to test the rule against")


class CustomRuleDryRunResponse(CamelCaseModel):
    """Response from a dry-run test."""

    rule_id: str
    rule_name: str
    matches: list[dict]
    match_count: int


class DeltaSyncResponse(CamelCaseModel):
    """Response for delta sync — rules modified since timestamp."""

    items: list[CustomRuleResponse]
    total: int
