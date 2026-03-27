"""Scan scheduling service with three-tier cascade resolution (D20 #39).

Schedule resolution follows the cascade: project -> group -> org -> none.
Org settings control whether projects may override the org default.

Usage::

    from app.services.scan_schedule_service import scan_schedule_service

    schedule = await scan_schedule_service.resolve_schedule(project_id, session)
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from croniter import croniter
from fastapi import HTTPException
from sqlalchemy import select

from app.models.organisation import Organisation
from app.models.project import Group, Project
from app.schemas.scan_schedule import SCHEDULE_PRESETS, ScheduleResponse
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


@dataclass
class ScheduleInfo:
    """Internal schedule representation."""

    cron: str | None
    tz: str
    source: str  # "project", "group", "org", "none"


class ScanScheduleService:
    """Manages scan schedule resolution and persistence."""

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    async def resolve_schedule(
        self,
        project_id: uuid.UUID,
        session: AsyncSession,
    ) -> ScheduleResponse:
        """Resolve the effective schedule for a project using cascade logic.

        Resolution order: project -> group -> org -> none.
        """
        # 1. Load project
        result = await session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        # Check project-level schedule
        if project.schedule_cron:
            return self._to_response(
                ScheduleInfo(cron=project.schedule_cron, tz=project.schedule_timezone, source="project")
            )

        # 2. Check group-level schedule
        result = await session.execute(select(Group).where(Group.id == project.group_id))
        group = result.scalar_one_or_none()
        if group and group.schedule_cron:
            return self._to_response(
                ScheduleInfo(cron=group.schedule_cron, tz=group.schedule_timezone, source="group")
            )

        # 3. Check org-level default
        result = await session.execute(select(Organisation).where(Organisation.id == project.org_id))
        org = result.scalar_one_or_none()
        if org and org.default_schedule_cron:
            return self._to_response(
                ScheduleInfo(cron=org.default_schedule_cron, tz=org.default_schedule_timezone, source="org")
            )

        return self._to_response(ScheduleInfo(cron=None, tz="UTC", source="none"))

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    async def save_project_schedule(
        self,
        project_id: uuid.UUID,
        cron_expr: str | None,
        tz: str,
        actor_id: uuid.UUID,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> ScheduleResponse:
        """Save or clear a project-level schedule.

        Validates that the org allows project schedule overrides.
        """
        result = await session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        # Check org override setting
        org_result = await session.execute(select(Organisation).where(Organisation.id == project.org_id))
        org = org_result.scalar_one_or_none()
        if org and not org.allow_project_schedule_override and cron_expr is not None:
            raise HTTPException(
                status_code=403,
                detail="Organisation does not allow project-level schedule overrides",
            )

        if cron_expr is not None:
            self._validate_cron(cron_expr)

        project.schedule_cron = cron_expr
        project.schedule_timezone = tz
        await session.flush()

        await audit_service.log(
            action_type="schedule.update",
            user_id=actor_id,
            org_id=org_id,
            resource_type="project",
            resource_id=project_id,
            details={"cron": cron_expr, "timezone": tz, "scope": "project"},
            session=session,
        )

        return await self.resolve_schedule(project_id, session)

    async def save_group_schedule(
        self,
        group_id: uuid.UUID,
        cron_expr: str | None,
        tz: str,
        actor_id: uuid.UUID,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> ScheduleResponse:
        """Save or clear a group-level schedule."""
        result = await session.execute(select(Group).where(Group.id == group_id))
        group = result.scalar_one_or_none()
        if group is None:
            raise HTTPException(status_code=404, detail="Group not found")

        if cron_expr is not None:
            self._validate_cron(cron_expr)

        group.schedule_cron = cron_expr
        group.schedule_timezone = tz
        await session.flush()

        await audit_service.log(
            action_type="schedule.update",
            user_id=actor_id,
            org_id=org_id,
            resource_type="group",
            resource_id=group_id,
            details={"cron": cron_expr, "timezone": tz, "scope": "group"},
            session=session,
        )

        # Return the first project schedule in this group for preview
        # (the actual cascade resolves per-project at scan time)
        return ScheduleResponse(
            cron=cron_expr,
            timezone=tz,
            source="group",
            next_run=self._next_run(cron_expr) if cron_expr else None,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def resolve_cron_from_preset(preset: str | None, cron: str | None) -> str | None:
        """Resolve a cron expression from preset name or raw cron string."""
        if preset:
            resolved = SCHEDULE_PRESETS.get(preset)
            if resolved is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown schedule preset: {preset}. Valid: {', '.join(SCHEDULE_PRESETS)}",
                )
            return resolved
        return cron

    @staticmethod
    def _validate_cron(expression: str) -> None:
        """Validate a cron expression. Raises 400 if invalid."""
        if not croniter.is_valid(expression):
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {expression}")

    @staticmethod
    def _next_run(expression: str) -> datetime:
        """Compute the next run time from a cron expression."""
        base = datetime.now(timezone.utc)
        cron = croniter(expression, base)
        return cron.get_next(datetime)

    def _to_response(self, info: ScheduleInfo) -> ScheduleResponse:
        """Convert internal ScheduleInfo to API response."""
        return ScheduleResponse(
            cron=info.cron,
            timezone=info.tz,
            source=info.source,
            next_run=self._next_run(info.cron) if info.cron else None,
        )


# Module-level singleton
scan_schedule_service = ScanScheduleService()
