"""Tests for bulk action service (D19)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.finding import Finding
from app.services.bulk_action_service import BulkActionService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    finding_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    status: str = "open",
    assigned_to: uuid.UUID | None = None,
) -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = finding_id or uuid.uuid4()
    f.org_id = org_id or uuid.uuid4()
    f.project_id = uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.status = status
    f.assigned_to = assigned_to
    f.reopen_count = 0
    f.last_reopened_at = None
    f.updated_at = datetime.now(timezone.utc)
    return f


def _make_actor(
    *,
    role: str = "security_manager",
    org_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> MagicMock:
    actor = MagicMock()
    actor.user_id = str(user_id or uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = role
    actor.assigned_group_id = None
    return actor


def _mock_session_with_findings(findings: list[MagicMock]) -> AsyncMock:
    """Build session that returns findings on execute (scalar_one_or_none for each)."""
    session = AsyncMock()
    results = []
    for f in findings:
        r = MagicMock()
        r.scalar_one_or_none.return_value = f
        results.append(r)
    session.execute = AsyncMock(side_effect=results)
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def svc() -> BulkActionService:
    return BulkActionService()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBulkAssign:
    """Bulk assign should assign all findings to a user."""

    @pytest.mark.asyncio
    async def test_bulk_assign(self, svc: BulkActionService) -> None:
        org_id = uuid.uuid4()
        assignee_id = uuid.uuid4()
        findings = [_make_finding(org_id=org_id) for _ in range(3)]
        actor = _make_actor(role="security_manager", org_id=org_id)
        session = _mock_session_with_findings(findings)

        with patch("app.services.bulk_action_service.finding_status_service") as mock_fss:
            mock_fss.assign = AsyncMock(side_effect=findings)
            result = await svc.execute(
                finding_ids=[f.id for f in findings],
                action="assign",
                params={"assignee_id": str(assignee_id)},
                actor=actor,
                session=session,
            )

        assert result.total == 3
        assert result.succeeded == 3
        assert result.failed == 0
        assert mock_fss.assign.call_count == 3


class TestBulkStatusChange:
    """Bulk status change should change status of all findings."""

    @pytest.mark.asyncio
    async def test_bulk_status_change(self, svc: BulkActionService) -> None:
        org_id = uuid.uuid4()
        findings = [_make_finding(org_id=org_id, status="open") for _ in range(2)]
        actor = _make_actor(role="security_engineer", org_id=org_id)
        session = _mock_session_with_findings(findings)

        with patch("app.services.bulk_action_service.finding_status_service") as mock_fss:
            mock_fss.change_status = AsyncMock(side_effect=findings)
            result = await svc.execute(
                finding_ids=[f.id for f in findings],
                action="status_change",
                params={"status": "in_review"},
                actor=actor,
                session=session,
            )

        assert result.total == 2
        assert result.succeeded == 2
        assert mock_fss.change_status.call_count == 2


class TestBulkMarkFPRequiresSMOA:
    """Bulk mark_fp should fail for developers."""

    @pytest.mark.asyncio
    async def test_bulk_mark_fp_requires_sm_oa(self, svc: BulkActionService) -> None:
        org_id = uuid.uuid4()
        findings = [_make_finding(org_id=org_id)]
        actor = _make_actor(role="developer", org_id=org_id)
        session = _mock_session_with_findings(findings)

        with patch("app.services.bulk_action_service.finding_status_service") as mock_fss:
            mock_fss.change_status = AsyncMock(side_effect=PermissionError("Insufficient role"))
            result = await svc.execute(
                finding_ids=[findings[0].id],
                action="mark_fp",
                params={"reason": "Not a finding"},
                actor=actor,
                session=session,
            )

        # Should report failure
        assert result.failed == 1
        assert result.results[0].success is False


class TestBulkRaiseFPRequestForDev:
    """Developer should be able to bulk raise FP requests."""

    @pytest.mark.asyncio
    async def test_bulk_raise_fp_request_for_dev(self, svc: BulkActionService) -> None:
        org_id = uuid.uuid4()
        findings = [_make_finding(org_id=org_id) for _ in range(2)]
        actor = _make_actor(role="developer", org_id=org_id)
        session = _mock_session_with_findings(findings)

        with patch("app.services.bulk_action_service.finding_request_service") as mock_frs:
            mock_frs.create_request = AsyncMock()
            result = await svc.execute(
                finding_ids=[f.id for f in findings],
                action="raise_fp_request",
                params={"justification": "These are not real findings"},
                actor=actor,
                session=session,
            )

        assert result.total == 2
        assert result.succeeded == 2
        assert mock_frs.create_request.call_count == 2


class TestRbacDevCannotBulkAssign:
    """Developer cannot bulk assign to others."""

    @pytest.mark.asyncio
    async def test_rbac_dev_cannot_bulk_assign(self, svc: BulkActionService) -> None:
        org_id = uuid.uuid4()
        other_user = uuid.uuid4()
        findings = [_make_finding(org_id=org_id)]
        actor = _make_actor(role="developer", org_id=org_id)
        session = _mock_session_with_findings(findings)

        with patch("app.services.bulk_action_service.finding_status_service") as mock_fss:
            mock_fss.assign = AsyncMock(side_effect=PermissionError("self-assign only"))
            result = await svc.execute(
                finding_ids=[findings[0].id],
                action="assign",
                params={"assignee_id": str(other_user)},
                actor=actor,
                session=session,
            )

        assert result.failed == 1
        assert result.results[0].success is False


class TestInvalidActionRejected:
    """An unsupported action should raise ValueError."""

    @pytest.mark.asyncio
    async def test_invalid_action_rejected(self, svc: BulkActionService) -> None:
        org_id = uuid.uuid4()
        actor = _make_actor(role="security_manager", org_id=org_id)
        session = AsyncMock()

        with pytest.raises(ValueError, match="[Uu]nsupported.*action"):
            await svc.execute(
                finding_ids=[uuid.uuid4()],
                action="delete_everything",
                params={},
                actor=actor,
                session=session,
            )
