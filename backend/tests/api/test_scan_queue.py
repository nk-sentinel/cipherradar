"""Tests for scan queue API with filters and pagination (D20 #38)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.scan import Scan, ScanStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scan(
    *,
    org_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    status: ScanStatus = ScanStatus.COMPLETED,
    project_name: str = "test-project",
) -> MagicMock:
    """Build a mock Scan with associated project."""
    s = MagicMock(spec=Scan)
    s.id = uuid.uuid4()
    s.org_id = org_id or uuid.uuid4()
    s.project_id = project_id or uuid.uuid4()
    s.status = status
    s.branch = "main"
    s.commit_sha = "abc123"
    s.findings_count = 5
    s.started_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
    s.completed_at = datetime(2026, 3, 1, 0, 5, tzinfo=timezone.utc)
    s.created_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
    s.environment = "dev"
    proj = MagicMock()
    proj.name = project_name
    s.project = proj
    return s


def _make_actor(
    *,
    role: str = "security_engineer",
    org_id: uuid.UUID | None = None,
) -> MagicMock:
    actor = MagicMock()
    actor.user_id = str(uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = role
    actor.scopes = []
    actor.assignment_level = "org"
    actor.assigned_group_id = None
    actor.assigned_project_ids = []
    return actor


def _make_request(query_params: dict[str, str] | None = None) -> MagicMock:
    """Build a mock Request with query_params."""
    req = MagicMock()
    req.query_params = query_params or {}
    return req


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_scans_returns_paginated() -> None:
    """list_scans returns paginated ScanQueueListResponse."""
    from app.schemas.scan import ScanQueueListResponse

    org_id = uuid.uuid4()
    scans = [_make_scan(org_id=org_id) for _ in range(3)]

    session = AsyncMock()
    # First call: count query
    count_result = MagicMock()
    count_result.scalar_one.return_value = 3
    # Second call: data query
    data_result = MagicMock()
    unique_mock = MagicMock()
    unique_mock.scalars.return_value.all.return_value = scans
    data_result.unique.return_value = unique_mock

    session.execute = AsyncMock(side_effect=[count_result, data_result])

    actor = _make_actor(org_id=org_id)

    with (
        patch("app.api.v1.scans.get_current_user", return_value=actor),
        patch("app.api.v1.scans.get_session", return_value=session),
    ):
        from app.api.v1.scans import list_scans

        result = await list_scans(
            request=_make_request(),
            page=1,
            per_page=25,
            status=None,
            project_id=None,
            trigger_type=None,
            user=actor,
            session=session,
        )

    assert result.total == 3
    assert len(result.items) == 3
    assert result.page == 1


@pytest.mark.asyncio
async def test_list_scans_filter_by_status() -> None:
    """list_scans with status filter returns only matching scans."""
    org_id = uuid.uuid4()
    scan = _make_scan(org_id=org_id, status=ScanStatus.QUEUED)

    session = AsyncMock()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 1
    data_result = MagicMock()
    unique_mock = MagicMock()
    unique_mock.scalars.return_value.all.return_value = [scan]
    data_result.unique.return_value = unique_mock
    session.execute = AsyncMock(side_effect=[count_result, data_result])

    actor = _make_actor(org_id=org_id)

    from app.api.v1.scans import list_scans

    result = await list_scans(
        request=_make_request(),
        page=1,
        per_page=25,
        status="queued",
        project_id=None,
        trigger_type=None,
        user=actor,
        session=session,
    )

    assert result.total == 1
    assert len(result.items) == 1


@pytest.mark.asyncio
async def test_list_scans_filter_by_project() -> None:
    """list_scans with project_id filter scopes to that project."""
    org_id = uuid.uuid4()
    pid = uuid.uuid4()
    scan = _make_scan(org_id=org_id, project_id=pid)

    session = AsyncMock()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 1
    data_result = MagicMock()
    unique_mock = MagicMock()
    unique_mock.scalars.return_value.all.return_value = [scan]
    data_result.unique.return_value = unique_mock
    session.execute = AsyncMock(side_effect=[count_result, data_result])

    actor = _make_actor(org_id=org_id)

    from app.api.v1.scans import list_scans

    result = await list_scans(
        request=_make_request(),
        page=1,
        per_page=25,
        status=None,
        project_id=pid,
        trigger_type=None,
        user=actor,
        session=session,
    )

    assert result.total == 1


@pytest.mark.asyncio
async def test_list_scans_rbac_scoped() -> None:
    """Scans are scoped to the user's org_id."""
    org_id = uuid.uuid4()

    session = AsyncMock()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    data_result = MagicMock()
    unique_mock = MagicMock()
    unique_mock.scalars.return_value.all.return_value = []
    data_result.unique.return_value = unique_mock
    session.execute = AsyncMock(side_effect=[count_result, data_result])

    actor = _make_actor(org_id=org_id)

    from app.api.v1.scans import list_scans

    result = await list_scans(
        request=_make_request(),
        page=1,
        per_page=25,
        status=None,
        project_id=None,
        trigger_type=None,
        user=actor,
        session=session,
    )

    assert result.total == 0
    assert result.items == []
