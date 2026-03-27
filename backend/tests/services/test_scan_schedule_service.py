"""Tests for scan schedule service (D20 #39)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services.scan_schedule_service import ScanScheduleService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(
    *,
    schedule_cron: str | None = None,
    schedule_timezone: str = "UTC",
    group_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
) -> MagicMock:
    p = MagicMock()
    p.id = uuid.uuid4()
    p.schedule_cron = schedule_cron
    p.schedule_timezone = schedule_timezone
    p.group_id = group_id or uuid.uuid4()
    p.org_id = org_id or uuid.uuid4()
    return p


def _make_group(
    *,
    schedule_cron: str | None = None,
    schedule_timezone: str = "UTC",
) -> MagicMock:
    g = MagicMock()
    g.id = uuid.uuid4()
    g.schedule_cron = schedule_cron
    g.schedule_timezone = schedule_timezone
    return g


def _make_org(
    *,
    default_schedule_cron: str | None = None,
    default_schedule_timezone: str = "UTC",
    allow_project_schedule_override: bool = True,
) -> MagicMock:
    o = MagicMock()
    o.id = uuid.uuid4()
    o.default_schedule_cron = default_schedule_cron
    o.default_schedule_timezone = default_schedule_timezone
    o.allow_project_schedule_override = allow_project_schedule_override
    return o


def _session_returning(*objects: MagicMock | None) -> AsyncMock:
    """Create a session mock that returns objects sequentially from execute calls."""
    session = AsyncMock()
    results = []
    for obj in objects:
        r = MagicMock()
        r.scalar_one_or_none.return_value = obj
        results.append(r)
    session.execute = AsyncMock(side_effect=results)
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

service = ScanScheduleService()


@pytest.mark.asyncio
async def test_resolve_cascade_project_level() -> None:
    """When project has a schedule, it takes priority."""
    project = _make_project(schedule_cron="0 3 * * *")
    session = _session_returning(project)

    result = await service.resolve_schedule(project.id, session)

    assert result.source == "project"
    assert result.cron == "0 3 * * *"
    assert result.next_run is not None


@pytest.mark.asyncio
async def test_resolve_cascade_group_level() -> None:
    """When project has no schedule, falls back to group."""
    project = _make_project(schedule_cron=None)
    group = _make_group(schedule_cron="0 4 * * 0")
    org = _make_org()  # not reached
    session = _session_returning(project, group)

    result = await service.resolve_schedule(project.id, session)

    assert result.source == "group"
    assert result.cron == "0 4 * * 0"


@pytest.mark.asyncio
async def test_falls_back_to_org() -> None:
    """When project and group have no schedule, falls back to org default."""
    project = _make_project(schedule_cron=None)
    group = _make_group(schedule_cron=None)
    org = _make_org(default_schedule_cron="0 2 * * *")
    session = _session_returning(project, group, org)

    result = await service.resolve_schedule(project.id, session)

    assert result.source == "org"
    assert result.cron == "0 2 * * *"


@pytest.mark.asyncio
async def test_resolve_returns_none_when_no_schedule() -> None:
    """When no level has a schedule, source is 'none'."""
    project = _make_project(schedule_cron=None)
    group = _make_group(schedule_cron=None)
    org = _make_org(default_schedule_cron=None)
    session = _session_returning(project, group, org)

    result = await service.resolve_schedule(project.id, session)

    assert result.source == "none"
    assert result.cron is None
    assert result.next_run is None


@pytest.mark.asyncio
async def test_override_setting_respected() -> None:
    """When org disallows project override, save_project_schedule raises 403."""
    project = _make_project(schedule_cron=None)
    org = _make_org(allow_project_schedule_override=False)
    session = _session_returning(project, org)

    with pytest.raises(HTTPException) as exc_info:
        await service.save_project_schedule(
            project_id=project.id,
            cron_expr="0 3 * * *",
            tz="UTC",
            actor_id=uuid.uuid4(),
            org_id=org.id,
            session=session,
        )

    assert exc_info.value.status_code == 403
    assert "override" in exc_info.value.detail.lower()


def test_preset_daily() -> None:
    """daily preset resolves to correct cron expression."""
    result = ScanScheduleService.resolve_cron_from_preset("daily", None)
    assert result == "0 2 * * *"


def test_preset_weekly() -> None:
    """weekly preset resolves to correct cron expression."""
    result = ScanScheduleService.resolve_cron_from_preset("weekly", None)
    assert result == "0 2 * * 0"


def test_invalid_cron_rejected() -> None:
    """Invalid cron expression raises 400."""
    with pytest.raises(HTTPException) as exc_info:
        ScanScheduleService._validate_cron("not a cron")

    assert exc_info.value.status_code == 400
    assert "invalid cron" in exc_info.value.detail.lower()


def test_unknown_preset_rejected() -> None:
    """Unknown preset name raises 400."""
    with pytest.raises(HTTPException) as exc_info:
        ScanScheduleService.resolve_cron_from_preset("hourly", None)

    assert exc_info.value.status_code == 400
    assert "unknown schedule preset" in exc_info.value.detail.lower()
