"""Scan schedule API routes (D20 #39).

Provides GET/PUT for project and group schedule management with
three-tier cascade resolution (project -> group -> org -> none).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.scan_schedule import ScheduleResponse, ScheduleUpdate
from app.services.scan_schedule_service import scan_schedule_service

router = APIRouter(tags=["scan-schedule"])


# ---------------------------------------------------------------------------
# Project schedule: OA, SM, SE
# ---------------------------------------------------------------------------


@router.get(
    "/projects/{project_id}/schedule",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
    ))],
)
async def get_project_schedule(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScheduleResponse:
    """Get the effective schedule for a project (cascade-resolved)."""
    return await scan_schedule_service.resolve_schedule(project_id, session)


@router.put(
    "/projects/{project_id}/schedule",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
    ))],
)
async def update_project_schedule(
    project_id: uuid.UUID,
    body: ScheduleUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScheduleResponse:
    """Set or clear the project-level scan schedule.

    Accepts either a named preset (daily, weekly, etc.) or a custom cron expression.
    The org must allow project schedule overrides for this to succeed.
    """
    cron_expr = scan_schedule_service.resolve_cron_from_preset(body.preset, body.cron)
    result = await scan_schedule_service.save_project_schedule(
        project_id=project_id,
        cron_expr=cron_expr,
        tz=body.timezone,
        actor_id=uuid.UUID(user.user_id),
        org_id=uuid.UUID(user.org_id),
        session=session,
    )
    await session.commit()
    return result


# ---------------------------------------------------------------------------
# Group schedule: OA, SM
# ---------------------------------------------------------------------------


@router.get(
    "/groups/{group_id}/schedule",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER,
    ))],
)
async def get_group_schedule(
    group_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScheduleResponse:
    """Get the schedule for a group."""
    from sqlalchemy import select

    from app.models.project import Group

    result = await session.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if group is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Group not found")

    next_run = None
    if group.schedule_cron:
        next_run = scan_schedule_service._next_run(group.schedule_cron)

    return ScheduleResponse(
        cron=group.schedule_cron,
        timezone=group.schedule_timezone,
        source="group",
        next_run=next_run,
    )


@router.put(
    "/groups/{group_id}/schedule",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER,
    ))],
)
async def update_group_schedule(
    group_id: uuid.UUID,
    body: ScheduleUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScheduleResponse:
    """Set or clear the group-level scan schedule.

    Accepts either a named preset or a custom cron expression.
    """
    cron_expr = scan_schedule_service.resolve_cron_from_preset(body.preset, body.cron)
    result = await scan_schedule_service.save_group_schedule(
        group_id=group_id,
        cron_expr=cron_expr,
        tz=body.timezone,
        actor_id=uuid.UUID(user.user_id),
        org_id=uuid.UUID(user.org_id),
        session=session,
    )
    await session.commit()
    return result
