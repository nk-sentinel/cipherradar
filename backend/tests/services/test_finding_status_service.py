"""Tests for finding status service (D14, D17)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.finding import Finding
from app.services.finding_status_service import FindingStatusService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    org_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    status: str = "open",
    assigned_to: uuid.UUID | None = None,
) -> MagicMock:
    """Build a mock Finding ORM object."""
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.org_id = org_id or uuid.uuid4()
    f.project_id = project_id or uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.status = status
    f.assigned_to = assigned_to
    f.reopen_count = 0
    f.last_reopened_at = None
    f.updated_at = datetime.now(timezone.utc)
    return f


def _make_actor(
    *,
    role: str = "security_engineer",
    org_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a mock AuthenticatedUser."""
    actor = MagicMock()
    actor.user_id = str(user_id or uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = role
    return actor


def _mock_session_returning_finding(finding: MagicMock) -> AsyncMock:
    """Build an AsyncMock session that returns the given finding from execute."""
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = finding
    session.execute = AsyncMock(return_value=result_mock)
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def svc() -> FindingStatusService:
    return FindingStatusService()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChangeStatusOpenToInReview:
    """Transition from open → in_review should succeed for SE."""

    @pytest.mark.asyncio
    async def test_change_status_open_to_in_review(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_engineer", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with patch("app.services.finding_status_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.change_status(
                finding_id=finding.id,
                new_status="in_review",
                actor=actor,
                session=session,
            )

        assert finding.status == "in_review"
        # History record should be added to session
        assert session.add.called


class TestChangeStatusRequiresReasonForRA:
    """Transition to risk_accepted requires a reason."""

    @pytest.mark.asyncio
    async def test_change_status_requires_reason_for_ra(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_manager", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with pytest.raises(ValueError, match="[Rr]eason.*required"):
            await svc.change_status(
                finding_id=finding.id,
                new_status="risk_accepted",
                actor=actor,
                session=session,
            )


class TestChangeStatusRequiresReasonForFP:
    """Transition to false_positive requires a reason."""

    @pytest.mark.asyncio
    async def test_change_status_requires_reason_for_fp(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_manager", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with pytest.raises(ValueError, match="[Rr]eason.*required"):
            await svc.change_status(
                finding_id=finding.id,
                new_status="false_positive",
                actor=actor,
                session=session,
            )


class TestInvalidTransitionRejected:
    """Invalid transitions (e.g., in_progress → risk_accepted) should be rejected."""

    @pytest.mark.asyncio
    async def test_invalid_transition_rejected(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="in_progress")
        actor = _make_actor(role="security_manager", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with pytest.raises(ValueError, match="[Ii]nvalid.*transition"):
            await svc.change_status(
                finding_id=finding.id,
                new_status="risk_accepted",
                actor=actor,
                session=session,
            )


class TestRbacDevCannotMarkFP:
    """Developer cannot directly mark a finding as false_positive."""

    @pytest.mark.asyncio
    async def test_rbac_dev_cannot_mark_fp(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="developer", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with pytest.raises(PermissionError, match="[Ii]nsufficient.*role"):
            await svc.change_status(
                finding_id=finding.id,
                new_status="false_positive",
                reason="Not a real finding",
                actor=actor,
                session=session,
            )


class TestRbacOnlySMOACanMarkRA:
    """Only SM and OA can mark risk_accepted."""

    @pytest.mark.asyncio
    async def test_rbac_only_sm_oa_can_mark_ra(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_engineer", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with pytest.raises(PermissionError, match="[Ii]nsufficient.*role"):
            await svc.change_status(
                finding_id=finding.id,
                new_status="risk_accepted",
                reason="Low impact",
                reason_category="low_impact",
                actor=actor,
                session=session,
            )


class TestStatusHistoryRecorded:
    """Every status change should create a FindingStatusHistory record."""

    @pytest.mark.asyncio
    async def test_status_history_recorded(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_engineer", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with patch("app.services.finding_status_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.change_status(
                finding_id=finding.id,
                new_status="in_review",
                actor=actor,
                session=session,
            )

        # At least one add() call should be a FindingStatusHistory
        from app.models.finding_status_history import FindingStatusHistory

        added_objects = [call[0][0] for call in session.add.call_args_list]
        history_entries = [o for o in added_objects if isinstance(o, FindingStatusHistory)]
        assert len(history_entries) == 1
        assert history_entries[0].old_status == "open"
        assert history_entries[0].new_status == "in_review"


class TestAuditLogOnStatusChange:
    """Status change should log to the audit service."""

    @pytest.mark.asyncio
    async def test_audit_log_on_status_change(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_engineer", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with patch("app.services.finding_status_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.change_status(
                finding_id=finding.id,
                new_status="in_review",
                actor=actor,
                session=session,
            )

            mock_audit.log.assert_awaited_once()
            call_kwargs = mock_audit.log.call_args[1]
            assert call_kwargs["action_type"] == "finding.status_change"
            assert call_kwargs["resource_type"] == "finding"


class TestAssignAutoTransitionsToInReview:
    """Assigning a finding should auto-transition status to in_review."""

    @pytest.mark.asyncio
    async def test_assign_auto_transitions_to_in_review(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="security_manager", org_id=org_id)
        assignee_id = uuid.uuid4()
        session = _mock_session_returning_finding(finding)

        with patch("app.services.finding_status_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.assign(
                finding_id=finding.id,
                assignee_id=assignee_id,
                actor=actor,
                session=session,
            )

        assert finding.assigned_to == assignee_id
        assert finding.status == "in_review"


class TestDevSelfAssignOnly:
    """Developer can only assign findings to themselves."""

    @pytest.mark.asyncio
    async def test_dev_self_assign_only(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        dev_id = uuid.uuid4()
        other_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="developer", org_id=org_id, user_id=dev_id)
        session = _mock_session_returning_finding(finding)

        with pytest.raises(PermissionError, match="[Aa]ssign.*self"):
            await svc.assign(
                finding_id=finding.id,
                assignee_id=other_id,
                actor=actor,
                session=session,
            )
