"""Tests for the centralized audit log service."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from app.services.audit_service import AuditService, audit_service


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def svc() -> AuditService:
    """Fresh AuditService instance."""
    return AuditService()


# ---------------------------------------------------------------------------
# Core logging
# ---------------------------------------------------------------------------


class TestAuditLogCreation:
    """Verify audit entries are created with correct fields."""

    @pytest.mark.asyncio
    async def test_log_entry_created_with_required_fields(self, svc: AuditService) -> None:
        """A log call with required fields should persist via session.add."""
        session = AsyncMock()
        org_id = uuid.uuid4()

        await svc.log(
            action_type="user.role_change",
            org_id=org_id,
            resource_type="user",
            session=session,
        )

        # session.add should have been called once with an AuditLog instance
        session.add.assert_called_once()
        added_obj = session.add.call_args[0][0]

        assert added_obj.action_type == "user.role_change"
        assert added_obj.org_id == org_id
        assert added_obj.resource_type == "user"
        assert added_obj.user_id is None
        assert added_obj.resource_id is None
        assert added_obj.details is None
        assert added_obj.ip_address is None
        assert added_obj.user_agent is None

        # flush should be called to persist immediately
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_log_entry_with_all_fields(self, svc: AuditService) -> None:
        """A log call with all optional fields should persist them correctly."""
        session = AsyncMock()
        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        resource_id = uuid.uuid4()

        await svc.log(
            action_type="finding.status_change",
            user_id=user_id,
            org_id=org_id,
            resource_type="finding",
            resource_id=resource_id,
            details={"old_status": "open", "new_status": "suppressed"},
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            session=session,
        )

        session.add.assert_called_once()
        added_obj = session.add.call_args[0][0]

        assert added_obj.action_type == "finding.status_change"
        assert added_obj.user_id == user_id
        assert added_obj.org_id == org_id
        assert added_obj.resource_type == "finding"
        assert added_obj.resource_id == resource_id
        assert added_obj.details == {"old_status": "open", "new_status": "suppressed"}
        assert added_obj.ip_address == "192.168.1.1"
        assert added_obj.user_agent == "Mozilla/5.0"

    @pytest.mark.asyncio
    async def test_log_raises_without_session(self, svc: AuditService) -> None:
        """Calling log() without a session should raise ValueError."""
        with pytest.raises(ValueError, match="session is required"):
            await svc.log(
                action_type="user.login",
                org_id=uuid.uuid4(),
                resource_type="user",
            )


class TestOptionalFields:
    """Verify optional fields are correctly nullable."""

    @pytest.mark.asyncio
    async def test_user_id_nullable(self, svc: AuditService) -> None:
        """user_id should be None when not provided (e.g. system-triggered events)."""
        session = AsyncMock()

        await svc.log(
            action_type="system.scan_scheduled",
            org_id=uuid.uuid4(),
            resource_type="scan",
            session=session,
        )

        added_obj = session.add.call_args[0][0]
        assert added_obj.user_id is None

    @pytest.mark.asyncio
    async def test_resource_id_nullable(self, svc: AuditService) -> None:
        """resource_id should be None when not provided."""
        session = AsyncMock()

        await svc.log(
            action_type="org.settings_change",
            org_id=uuid.uuid4(),
            resource_type="organisation",
            session=session,
        )

        added_obj = session.add.call_args[0][0]
        assert added_obj.resource_id is None

    @pytest.mark.asyncio
    async def test_details_nullable(self, svc: AuditService) -> None:
        """details should be None when not provided."""
        session = AsyncMock()

        await svc.log(
            action_type="scan.started",
            org_id=uuid.uuid4(),
            resource_type="scan",
            session=session,
        )

        added_obj = session.add.call_args[0][0]
        assert added_obj.details is None

    @pytest.mark.asyncio
    async def test_ip_address_nullable(self, svc: AuditService) -> None:
        """ip_address should be None when not provided."""
        session = AsyncMock()

        await svc.log(
            action_type="user.login",
            org_id=uuid.uuid4(),
            resource_type="user",
            session=session,
        )

        added_obj = session.add.call_args[0][0]
        assert added_obj.ip_address is None

    @pytest.mark.asyncio
    async def test_user_agent_nullable(self, svc: AuditService) -> None:
        """user_agent should be None when not provided."""
        session = AsyncMock()

        await svc.log(
            action_type="user.login",
            org_id=uuid.uuid4(),
            resource_type="user",
            session=session,
        )

        added_obj = session.add.call_args[0][0]
        assert added_obj.user_agent is None


class TestActionTypeIndexed:
    """The action_type column should be indexed for efficient filtering."""

    def test_action_type_column_is_indexed(self) -> None:
        """AuditLog.action_type should have index=True in its column definition."""
        from app.models.audit_log import AuditLog

        col = AuditLog.__table__.columns["action_type"]
        assert col.index is True, "action_type column must be indexed for filtering"

    def test_user_id_column_is_indexed(self) -> None:
        """AuditLog.user_id should be indexed for actor-based queries."""
        from app.models.audit_log import AuditLog

        col = AuditLog.__table__.columns["user_id"]
        assert col.index is True

    def test_org_id_column_is_indexed(self) -> None:
        """AuditLog.org_id should be indexed for tenant filtering."""
        from app.models.audit_log import AuditLog

        col = AuditLog.__table__.columns["org_id"]
        assert col.index is True


class TestModuleSingleton:
    """Verify that a module-level singleton is exported."""

    def test_singleton_exists(self) -> None:
        assert audit_service is not None
        assert isinstance(audit_service, AuditService)
