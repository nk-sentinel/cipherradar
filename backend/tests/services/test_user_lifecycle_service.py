"""Tests for user lifecycle service (D9)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.roles import Role
from app.models.api_key import APIKey
from app.models.user import User
from app.services.user_lifecycle_service import UserLifecycleService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG_ID = uuid.uuid4()
_ACTOR_ID = uuid.uuid4()


def _make_user(
    *,
    role: str = "developer",
    disabled_at: datetime | None = None,
    deleted_at: datetime | None = None,
    org_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a mock User ORM object."""
    u = MagicMock(spec=User)
    u.id = uuid.uuid4()
    u.email = "target@example.com"
    u.role = role
    u.org_id = org_id or _ORG_ID
    u.disabled_at = disabled_at
    u.deleted_at = deleted_at
    u.is_active = disabled_at is None
    u.updated_at = datetime.now(UTC)
    return u


def _make_api_key(*, scopes: list[str] | None = None) -> MagicMock:
    """Build a mock APIKey ORM object."""
    k = MagicMock(spec=APIKey)
    k.id = uuid.uuid4()
    k.scopes = scopes or ["scan:read", "scan:write", "project:write"]
    k.revoked_at = None
    return k


def _mock_session_user(
    user: MagicMock | None,
    *,
    oa_count: int = 2,
    keys: list[MagicMock] | None = None,
) -> AsyncMock:
    """Build an AsyncMock session returning user + OA count + keys."""
    session = AsyncMock()

    call_count = 0

    async def _execute(stmt):
        nonlocal call_count
        call_count += 1
        result = MagicMock()
        if call_count == 1:
            # First call: user lookup
            result.scalar_one_or_none.return_value = user
        elif call_count == 2:
            # Second call: OA count check
            result.scalar.return_value = oa_count
        elif call_count == 3:
            # Third call: keys for scope check/revocation
            scalars_mock = MagicMock()
            scalars_mock.all.return_value = keys or []
            result.scalars.return_value = scalars_mock
        else:
            # Additional calls: return empty
            result.scalar.return_value = 0
            scalars_mock = MagicMock()
            scalars_mock.all.return_value = []
            result.scalars.return_value = scalars_mock
        return result

    session.execute = _execute
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChangeRole:
    @pytest.mark.asyncio
    async def test_change_role_success(self) -> None:
        service = UserLifecycleService()
        user = _make_user(role="developer")
        session = _mock_session_user(user, keys=[])

        with patch("app.services.user_lifecycle_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            old_role, revoked = await service.change_role(
                target_user_id=str(user.id),
                new_role="security_engineer",
                actor_id=str(_ACTOR_ID),
                actor_org_id=str(_ORG_ID),
                session=session,
            )

        assert old_role == "developer"
        assert user.role == "security_engineer"
        assert revoked == 0

    @pytest.mark.asyncio
    async def test_downgrade_revokes_over_scoped_keys(self) -> None:
        service = UserLifecycleService()
        user = _make_user(role="org_admin")
        key = _make_api_key(scopes=["scan:read", "scan:write", "project:write"])
        session = _mock_session_user(user, oa_count=2, keys=[key])

        with patch("app.services.user_lifecycle_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            old_role, revoked = await service.change_role(
                target_user_id=str(user.id),
                new_role="guest",
                actor_id=str(_ACTOR_ID),
                actor_org_id=str(_ORG_ID),
                session=session,
            )

        assert old_role == "org_admin"
        assert revoked == 1
        assert key.revoked_at is not None

    @pytest.mark.asyncio
    async def test_last_oa_protection(self) -> None:
        service = UserLifecycleService()
        user = _make_user(role="org_admin")
        session = _mock_session_user(user, oa_count=1, keys=[])

        from fastapi import HTTPException

        with patch("app.services.user_lifecycle_service.audit_service"):
            with pytest.raises(HTTPException) as exc_info:
                await service.change_role(
                    target_user_id=str(user.id),
                    new_role="developer",
                    actor_id=str(_ACTOR_ID),
                    actor_org_id=str(_ORG_ID),
                    session=session,
                )
        assert exc_info.value.status_code == 400
        assert "last Org Admin" in exc_info.value.detail


class TestDisable:
    @pytest.mark.asyncio
    async def test_disable_suspends_keys(self) -> None:
        service = UserLifecycleService()
        user = _make_user(role="developer")
        key = _make_api_key()
        # Session: first call returns user, second returns OA count, third returns keys
        session = AsyncMock()
        call_count = 0

        async def _execute(stmt):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                result.scalar_one_or_none.return_value = user
            elif call_count == 2:
                scalars_mock = MagicMock()
                scalars_mock.all.return_value = [key]
                result.scalars.return_value = scalars_mock
            return result

        session.execute = _execute

        with patch("app.services.user_lifecycle_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.disable(
                target_user_id=str(user.id),
                actor_id=str(_ACTOR_ID),
                actor_org_id=str(_ORG_ID),
                session=session,
            )

        assert user.disabled_at is not None
        assert user.is_active is False
        assert key.revoked_at is not None


class TestEnable:
    @pytest.mark.asyncio
    async def test_enable_unsuspends(self) -> None:
        service = UserLifecycleService()
        disabled_time = datetime.now(UTC)
        user = _make_user(role="developer", disabled_at=disabled_time)
        key = _make_api_key()
        key.revoked_at = disabled_time

        session = AsyncMock()
        call_count = 0

        async def _execute(stmt):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                result.scalar_one_or_none.return_value = user
            elif call_count == 2:
                scalars_mock = MagicMock()
                scalars_mock.all.return_value = [key]
                result.scalars.return_value = scalars_mock
            return result

        session.execute = _execute

        with patch("app.services.user_lifecycle_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.enable(
                target_user_id=str(user.id),
                actor_id=str(_ACTOR_ID),
                actor_org_id=str(_ORG_ID),
                session=session,
            )

        assert user.disabled_at is None
        assert user.is_active is True
        assert key.revoked_at is None


class TestDelete:
    @pytest.mark.asyncio
    async def test_delete_requires_disabled(self) -> None:
        service = UserLifecycleService()
        user = _make_user(role="developer")  # not disabled
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = user
        session.execute = AsyncMock(return_value=result)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.delete(
                target_user_id=str(user.id),
                actor_id=str(_ACTOR_ID),
                actor_org_id=str(_ORG_ID),
                session=session,
            )
        assert exc_info.value.status_code == 400
        assert "disabled" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_delete_sets_deleted_at(self) -> None:
        service = UserLifecycleService()
        user = _make_user(role="developer", disabled_at=datetime.now(UTC))
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = user
        session.execute = AsyncMock(return_value=result)

        with patch("app.services.user_lifecycle_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.delete(
                target_user_id=str(user.id),
                actor_id=str(_ACTOR_ID),
                actor_org_id=str(_ORG_ID),
                session=session,
            )

        assert user.deleted_at is not None
        mock_audit.log.assert_called_once()
