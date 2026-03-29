"""Tests for finding assignment notification (D17)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.finding import Finding
from app.models.notification import Notification
from app.services.finding_status_service import FindingStatusService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    org_id: uuid.UUID | None = None,
    status: str = "open",
    name: str = "AES-128",
) -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.org_id = org_id or uuid.uuid4()
    f.project_id = uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.status = status
    f.assigned_to = None
    f.name = name
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
    return actor


def _mock_session_returning_finding(finding: MagicMock) -> AsyncMock:
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


class TestAssignmentNotification:
    """When a finding is assigned, a notification should be created for the assignee."""

    @pytest.mark.asyncio
    async def test_notification_created_on_assign(self, svc: FindingStatusService) -> None:
        org_id = uuid.uuid4()
        assignee_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id, name="Weak RSA-1024 key")
        actor = _make_actor(role="security_manager", org_id=org_id)
        session = _mock_session_returning_finding(finding)

        with patch("app.services.finding_status_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.assign(
                finding_id=finding.id,
                assignee_id=assignee_id,
                actor=actor,
                session=session,
            )

        # Check that a Notification was added to the session
        added_objects = [call[0][0] for call in session.add.call_args_list]
        notifications = [o for o in added_objects if isinstance(o, Notification)]
        assert len(notifications) == 1

        notif = notifications[0]
        assert notif.user_id == assignee_id
        assert notif.org_id == org_id
        assert notif.trigger_type == "finding_assigned"
        assert "assigned" in notif.title.lower()

    @pytest.mark.asyncio
    async def test_notification_not_created_for_self_assign(self, svc: FindingStatusService) -> None:
        """If a user assigns a finding to themselves, still create notification (they opted in)."""
        org_id = uuid.uuid4()
        user_id = uuid.uuid4()
        finding = _make_finding(org_id=org_id)
        actor = _make_actor(role="developer", org_id=org_id, user_id=user_id)
        session = _mock_session_returning_finding(finding)

        with patch("app.services.finding_status_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.assign(
                finding_id=finding.id,
                assignee_id=user_id,
                actor=actor,
                session=session,
            )

        added_objects = [call[0][0] for call in session.add.call_args_list]
        notifications = [o for o in added_objects if isinstance(o, Notification)]
        # Notification should still be created (user can dismiss it)
        assert len(notifications) == 1
