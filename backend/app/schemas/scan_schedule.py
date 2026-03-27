"""Schemas for scan scheduling (D20 #39)."""

from __future__ import annotations

from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import Field

from app.schemas.base import CamelCaseModel

# Predefined schedule presets
SCHEDULE_PRESETS = {
    "daily": "0 2 * * *",       # Daily at 02:00
    "weekly": "0 2 * * 0",      # Weekly on Sunday at 02:00
    "biweekly": "0 2 1,15 * *", # 1st and 15th at 02:00
    "monthly": "0 2 1 * *",     # 1st of month at 02:00
}


class ScheduleResponse(CamelCaseModel):
    """Resolved scan schedule with source information."""

    cron: str | None = None
    timezone: str = "UTC"
    source: str = Field(description="Where the schedule comes from: project, group, org, or none")
    next_run: datetime | None = None


class ScheduleUpdate(CamelCaseModel):
    """Request to update a scan schedule."""

    preset: str | None = Field(default=None, description="Named preset: daily, weekly, biweekly, monthly")
    cron: str | None = Field(default=None, description="Custom cron expression (5-field)")
    timezone: str = Field(default="UTC", description="IANA timezone name")
