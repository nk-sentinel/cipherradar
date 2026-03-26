"""Pydantic schemas for rule effectiveness analytics (D16)."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from app.schemas.base import CamelCaseModel


class TrendPoint(CamelCaseModel):
    """A single data point in the findings-per-scan trend."""

    scan_id: uuid.UUID
    count: int
    scanned_at: datetime


class RuleAnalytics(CamelCaseModel):
    """Full analytics for a single rule within a time window."""

    rule_id: str
    total_findings: int
    active_findings: int
    fp_rate: float
    ra_rate: float
    fix_rate: float
    mttr_seconds: float | None
    trend: list[TrendPoint]
    time_window: str


class RuleSummary(CamelCaseModel):
    """Summary row for the rules table view."""

    rule_id: str
    total_findings: int
    fp_rate: float
    fix_rate: float
    mttr_seconds: float | None
    warning: bool  # True if fp_rate > 50 or fix_rate < 10
