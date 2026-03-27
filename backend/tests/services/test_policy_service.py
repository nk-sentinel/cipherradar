"""Tests for policy cascade service (D26)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser
from app.models.policy_override import PolicyOverride
from app.services.policy_service import PolicyService


_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()
_GROUP_ID = uuid.uuid4()
_PROJECT_ID = uuid.uuid4()


def _make_actor(role: str = "org_admin") -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(_USER_ID),
        org_id=str(_ORG_ID),
        role=role,
        scopes=[],
    )


def _make_override(
    rule_id: str = "no-broken-algorithms",
    action: str = "ignore",
    *,
    project_id: uuid.UUID | None = None,
    group_id: uuid.UUID | None = None,
) -> MagicMock:
    ov = MagicMock(spec=PolicyOverride)
    ov.id = uuid.uuid4()
    ov.org_id = _ORG_ID
    ov.project_id = project_id
    ov.group_id = group_id
    ov.framework = "default"
    ov.rule_id = rule_id
    ov.action = action
    ov.reason = "test reason"
    ov.created_by = _USER_ID
    return ov


class TestResolvePolicy:
    """Test cascade resolution."""

    @pytest.mark.asyncio
    async def test_default_rules_returned_when_no_overrides(self) -> None:
        svc = PolicyService()
        session = AsyncMock()

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        session.execute = AsyncMock(return_value=mock_result)

        result = await svc.resolve_policy(str(_ORG_ID), session)

        assert result["scope"] == "org"
        assert len(result["rules"]) == 6
        assert result["locked_rules"] == []

    @pytest.mark.asyncio
    async def test_org_override_applied(self) -> None:
        svc = PolicyService()
        session = AsyncMock()

        override = _make_override(rule_id="no-ecb-mode", action="ignore")

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [override]
        mock_result.scalars.return_value = mock_scalars
        session.execute = AsyncMock(return_value=mock_result)

        result = await svc.resolve_policy(str(_ORG_ID), session)

        ecb_rule = next(r for r in result["rules"] if r["id"] == "no-ecb-mode")
        assert ecb_rule["action"] == "ignore"

    @pytest.mark.asyncio
    async def test_locked_rule_blocks_lower_override(self) -> None:
        svc = PolicyService()

        org_lock = _make_override(rule_id="no-hardcoded-keys", action="lock")
        group_override = _make_override(
            rule_id="no-hardcoded-keys", action="ignore", group_id=_GROUP_ID,
        )

        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            scalars = MagicMock()
            if call_count == 1:
                # Org-level overrides
                scalars.all.return_value = [org_lock]
            elif call_count == 2:
                # Group-level overrides (should be filtered)
                scalars.all.return_value = [group_override]
            else:
                scalars.all.return_value = []
            result.scalars.return_value = scalars
            return result

        session = AsyncMock()
        session.execute = mock_execute

        result = await svc.resolve_policy(
            str(_ORG_ID), session, group_id=str(_GROUP_ID),
        )

        assert "no-hardcoded-keys" in result["locked_rules"]
        # The locked rule's action should NOT be overridden to 'ignore'
        key_rule = next(r for r in result["rules"] if r["id"] == "no-hardcoded-keys")
        assert key_rule["action"] != "ignore"


class TestSavePolicy:
    """Test saving policy overrides."""

    @pytest.mark.asyncio
    async def test_save_org_level_override(self) -> None:
        svc = PolicyService()
        session = AsyncMock()
        actor = _make_actor(role="org_admin")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.policy_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.save_policy(
                org_id=str(_ORG_ID),
                rule_id="no-ecb-mode",
                action="ignore",
                actor=actor,
                session=session,
            )

        assert result["saved"] is True
        assert session.add.call_count >= 1

    @pytest.mark.asyncio
    async def test_save_rejects_locked_rule(self) -> None:
        svc = PolicyService()
        actor = _make_actor(role="security_manager")

        # Mock org-level overrides with a lock
        org_lock = _make_override(rule_id="no-hardcoded-keys", action="lock")

        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                # Org-level overrides
                scalars = MagicMock()
                scalars.all.return_value = [org_lock]
                result.scalars.return_value = scalars
            else:
                result.scalar_one_or_none.return_value = None
            return result

        session = AsyncMock()
        session.execute = mock_execute

        with pytest.raises(ValueError, match="locked"):
            await svc.save_policy(
                org_id=str(_ORG_ID),
                rule_id="no-hardcoded-keys",
                action="ignore",
                actor=actor,
                session=session,
                group_id=str(_GROUP_ID),
            )


class TestLockEnforcement:
    """Test that lock mechanism works correctly."""

    @pytest.mark.asyncio
    async def test_only_oa_can_lock(self) -> None:
        svc = PolicyService()
        session = AsyncMock()
        actor = _make_actor(role="security_manager")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        session.execute = AsyncMock(return_value=mock_result)

        with pytest.raises(PermissionError, match="Org Admin"):
            await svc.save_policy(
                org_id=str(_ORG_ID),
                rule_id="no-ecb-mode",
                action="lock",
                actor=actor,
                session=session,
            )

    @pytest.mark.asyncio
    async def test_oa_can_lock(self) -> None:
        svc = PolicyService()
        session = AsyncMock()
        actor = _make_actor(role="org_admin")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.policy_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.save_policy(
                org_id=str(_ORG_ID),
                rule_id="no-ecb-mode",
                action="lock",
                actor=actor,
                session=session,
            )

        assert result["saved"] is True


class TestRBAC:
    """Verify role enforcement."""

    @pytest.mark.asyncio
    async def test_sm_cannot_modify_org_policy(self) -> None:
        svc = PolicyService()
        session = AsyncMock()
        actor = _make_actor(role="security_manager")

        with pytest.raises(PermissionError):
            await svc.save_policy(
                org_id=str(_ORG_ID),
                rule_id="no-ecb-mode",
                action="ignore",
                actor=actor,
                session=session,
                # No project_id or group_id = org level
            )

    @pytest.mark.asyncio
    async def test_developer_cannot_modify_any_policy(self) -> None:
        svc = PolicyService()
        session = AsyncMock()
        actor = _make_actor(role="developer")

        with pytest.raises(PermissionError):
            await svc.save_policy(
                org_id=str(_ORG_ID),
                rule_id="no-ecb-mode",
                action="ignore",
                actor=actor,
                session=session,
                project_id=str(_PROJECT_ID),
            )
