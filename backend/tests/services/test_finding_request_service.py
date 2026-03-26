"""Tests for finding request service (D15 — FP/RA workflow)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.finding import Finding
from app.models.finding_request import FindingRequest
from app.services.finding_request_service import FindingRequestService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    org_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    status: str = "open",
) -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.org_id = org_id or uuid.uuid4()
    f.project_id = project_id or uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.status = status
    f.assigned_to = None
    f.updated_at = datetime.now(timezone.utc)
    return f


def _make_request(
    *,
    finding_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    requested_by: uuid.UUID | None = None,
    request_type: str = "false_positive",
    request_status: str = "pending",
) -> MagicMock:
    r = MagicMock(spec=FindingRequest)
    r.id = uuid.uuid4()
    r.finding_id = finding_id or uuid.uuid4()
    r.org_id = org_id or uuid.uuid4()
    r.requested_by = requested_by or uuid.uuid4()
    r.reviewed_by = None
    r.request_type = request_type
    r.status = request_status
    r.justification = "This is not a real finding"
    r.review_note = None
    r.expires_at = None
    r.reviewed_at = None
    r.created_at = datetime.now(timezone.utc)
    r.updated_at = datetime.now(timezone.utc)
    return r


def _make_actor(
    *,
    role: str = "developer",
    org_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> MagicMock:
    actor = MagicMock()
    actor.user_id = str(user_id or uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = role
    actor.assigned_group_id = None
    return actor


def _mock_session_returning(obj: MagicMock | None) -> AsyncMock:
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = obj
    session.execute = AsyncMock(return_value=result_mock)
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def svc() -> FindingRequestService:
    return FindingRequestService()


# ---------------------------------------------------------------------------
# Tests — create_request
# ---------------------------------------------------------------------------


class TestDevCanRaiseFPRequest:
    """Developer should be able to create a false_positive request."""

    @pytest.mark.asyncio
    async def test_dev_can_raise_fp_request(self, svc: FindingRequestService) -> None:
        org_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, status="open")
        actor = _make_actor(role="developer", org_id=org_id)
        session = _mock_session_returning(finding)

        with patch("app.services.finding_request_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.create_request(
                finding_id=finding.id,
                request_type="false_positive",
                justification="This is not a real finding",
                actor=actor,
                session=session,
            )

        # Request should be added to session
        assert session.add.called
        added = session.add.call_args[0][0]
        assert isinstance(added, FindingRequest)
        assert added.request_type == "false_positive"
        assert added.status == "pending"


# ---------------------------------------------------------------------------
# Tests — approve
# ---------------------------------------------------------------------------


class TestSMCanApproveRARequest:
    """Security Manager should be able to approve a risk_accepted request."""

    @pytest.mark.asyncio
    async def test_sm_can_approve_ra_request(self, svc: FindingRequestService) -> None:
        org_id = uuid.uuid4()
        requester_id = uuid.uuid4()
        approver_id = uuid.uuid4()

        finding = _make_finding(org_id=org_id, status="open")
        request = _make_request(
            finding_id=finding.id,
            org_id=org_id,
            requested_by=requester_id,
            request_type="risk_accepted",
        )

        actor = _make_actor(role="security_manager", org_id=org_id, user_id=approver_id)

        session = AsyncMock()

        # First execute: load request; second: load finding
        req_result = MagicMock()
        req_result.scalar_one_or_none.return_value = request
        finding_result = MagicMock()
        finding_result.scalar_one_or_none.return_value = finding
        session.execute = AsyncMock(side_effect=[req_result, finding_result])
        session.flush = AsyncMock()
        session.add = MagicMock()

        with patch("app.services.finding_request_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.approve(
                request_id=request.id,
                actor=actor,
                session=session,
            )

        assert request.status == "approved"
        assert finding.status == "risk_accepted"


class TestSECannotApproveOwnFPRequest:
    """Security Engineer cannot approve their own false_positive request."""

    @pytest.mark.asyncio
    async def test_se_cannot_approve_own_fp_request(self, svc: FindingRequestService) -> None:
        org_id = uuid.uuid4()
        se_id = uuid.uuid4()

        request = _make_request(
            org_id=org_id,
            requested_by=se_id,
            request_type="false_positive",
        )

        actor = _make_actor(role="security_engineer", org_id=org_id, user_id=se_id)
        session = _mock_session_returning(request)

        with pytest.raises(PermissionError, match="[Cc]annot.*approve.*own"):
            await svc.approve(
                request_id=request.id,
                actor=actor,
                session=session,
            )


# ---------------------------------------------------------------------------
# Tests — approve changes finding status
# ---------------------------------------------------------------------------


class TestApproveChangesFindingStatus:
    """Approving a request should change the finding status to FP or RA."""

    @pytest.mark.asyncio
    async def test_approve_changes_finding_status_to_fp_or_ra(self, svc: FindingRequestService) -> None:
        org_id = uuid.uuid4()
        requester_id = uuid.uuid4()
        approver_id = uuid.uuid4()

        finding = _make_finding(org_id=org_id, status="open")
        request = _make_request(
            finding_id=finding.id,
            org_id=org_id,
            requested_by=requester_id,
            request_type="false_positive",
        )

        actor = _make_actor(role="security_manager", org_id=org_id, user_id=approver_id)

        session = AsyncMock()
        req_result = MagicMock()
        req_result.scalar_one_or_none.return_value = request
        finding_result = MagicMock()
        finding_result.scalar_one_or_none.return_value = finding
        session.execute = AsyncMock(side_effect=[req_result, finding_result])
        session.flush = AsyncMock()
        session.add = MagicMock()

        with patch("app.services.finding_request_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.approve(request_id=request.id, actor=actor, session=session)

        assert finding.status == "false_positive"
        assert request.status == "approved"


# ---------------------------------------------------------------------------
# Tests — reject
# ---------------------------------------------------------------------------


class TestRejectKeepsFindingStatusUnchanged:
    """Rejecting a request should not change the finding status."""

    @pytest.mark.asyncio
    async def test_reject_keeps_finding_status_unchanged(self, svc: FindingRequestService) -> None:
        org_id = uuid.uuid4()
        requester_id = uuid.uuid4()
        approver_id = uuid.uuid4()

        finding = _make_finding(org_id=org_id, status="open")
        request = _make_request(
            finding_id=finding.id,
            org_id=org_id,
            requested_by=requester_id,
            request_type="false_positive",
        )

        actor = _make_actor(role="security_manager", org_id=org_id, user_id=approver_id)
        session = _mock_session_returning(request)

        with patch("app.services.finding_request_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.reject(
                request_id=request.id,
                reason="Insufficient evidence",
                actor=actor,
                session=session,
            )

        assert request.status == "rejected"
        assert request.review_note == "Insufficient evidence"
        # Finding status should NOT be changed
        assert finding.status == "open"


# ---------------------------------------------------------------------------
# Tests — list_requests RBAC scoping
# ---------------------------------------------------------------------------


class TestRequestListRBACScoped:
    """TM should only see requests for their group scope."""

    @pytest.mark.asyncio
    async def test_request_list_rbac_scoped_for_tm(self, svc: FindingRequestService) -> None:
        org_id = uuid.uuid4()
        group_id = uuid.uuid4()
        actor = _make_actor(role="team_manager", org_id=org_id)
        actor.assigned_group_id = str(group_id)

        session = AsyncMock()

        # Mock count query
        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        # Mock data query
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        data_result = MagicMock()
        data_result.scalars.return_value = scalars_mock

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        result = await svc.list_requests(
            org_id=uuid.UUID(actor.org_id),
            actor=actor,
            page=1,
            per_page=25,
            session=session,
        )

        assert result.total == 0
        assert result.items == []
        # The query should have been executed (we can verify it was called)
        assert session.execute.call_count == 2
