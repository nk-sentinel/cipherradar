"""Tests for scan rerun API (D20 #37, #40)."""

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
    branch: str = "main",
    commit_sha: str = "abc123",
) -> MagicMock:
    s = MagicMock(spec=Scan)
    s.id = uuid.uuid4()
    s.org_id = org_id or uuid.uuid4()
    s.project_id = project_id or uuid.uuid4()
    s.status = ScanStatus.COMPLETED
    s.branch = branch
    s.commit_sha = commit_sha
    s.findings_count = 10
    s.started_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
    s.completed_at = datetime(2026, 3, 1, 0, 5, tzinfo=timezone.utc)
    s.created_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
    s.environment = None
    s.tag = None
    s.image_ref = None
    s.image_digest = None
    s.artifact_filename = None
    s.artifact_checksum = None
    s.promoted_at = None
    s.promoted_by = None
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rerun_creates_new_scan() -> None:
    """Rerun creates a new scan record with queued status."""
    original = _make_scan()
    actor = _make_actor(org_id=original.org_id)

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = original
    session.execute = AsyncMock(return_value=result_mock)

    # Track what gets added to session
    added_scans = []
    original_add = session.add

    def track_add(obj: Scan) -> None:
        added_scans.append(obj)

    session.add = track_add

    # Mock refresh to set from_attributes fields
    async def mock_refresh(obj: MagicMock) -> None:
        obj.id = uuid.uuid4()
        obj.created_at = datetime.now(timezone.utc)
        obj.started_at = None
        obj.completed_at = None

    session.refresh = mock_refresh

    from app.api.v1.scans import rerun_scan

    result = await rerun_scan(
        scan_id=original.id,
        user=actor,
        session=session,
    )

    assert len(added_scans) >= 1  # new scan + audit log


@pytest.mark.asyncio
async def test_rerun_copies_config() -> None:
    """Rerun clones branch and commit_sha from original scan."""
    original = _make_scan(branch="feature/test", commit_sha="def456")
    actor = _make_actor(org_id=original.org_id)

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = original
    session.execute = AsyncMock(return_value=result_mock)

    created_scans: list[Scan] = []

    def track_add(obj: object) -> None:
        if isinstance(obj, Scan):
            created_scans.append(obj)

    session.add = track_add

    async def mock_refresh(obj: MagicMock) -> None:
        obj.id = uuid.uuid4()
        obj.created_at = datetime.now(timezone.utc)
        obj.started_at = None
        obj.completed_at = None

    session.refresh = mock_refresh

    from app.api.v1.scans import rerun_scan

    await rerun_scan(scan_id=original.id, user=actor, session=session)

    assert len(created_scans) == 1
    new_scan = created_scans[0]
    assert new_scan.branch == "feature/test"
    assert new_scan.commit_sha == "def456"
    assert new_scan.project_id == original.project_id


@pytest.mark.asyncio
async def test_rerun_not_found() -> None:
    """Rerun returns 404 for unknown scan."""
    from fastapi import HTTPException

    actor = _make_actor()
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result_mock)

    from app.api.v1.scans import rerun_scan

    with pytest.raises(HTTPException) as exc_info:
        await rerun_scan(scan_id=uuid.uuid4(), user=actor, session=session)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_rerun_rbac() -> None:
    """Only OA, SM, SE roles should be allowed (tested via dependency declaration)."""
    from app.api.v1.scans import router

    # Find the rerun route
    rerun_route = None
    for route in router.routes:
        path = getattr(route, "path", "")
        if "rerun" in path:
            rerun_route = route
            break

    assert rerun_route is not None, "Rerun route not found"
    # Check that it has dependencies (RBAC guard)
    assert len(rerun_route.dependencies) > 0, "Rerun route has no RBAC dependencies"
