"""Tests for custom rule management service (D27)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser
from app.models.custom_rule import CustomRule
from app.services.custom_rule_service import CustomRuleService, validate_opengrep_rule


_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()


def _make_actor(role: str = "org_admin") -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(_USER_ID),
        org_id=str(_ORG_ID),
        role=role,
        scopes=[],
    )


def _make_rule(
    name: str = "test-rule",
    language: str = "python",
    pattern_type: str = "opengrep",
) -> MagicMock:
    r = MagicMock(spec=CustomRule)
    r.id = uuid.uuid4()
    r.org_id = _ORG_ID
    r.name = name
    r.description = "Test rule"
    r.language = language
    r.pattern_type = pattern_type
    r.pattern = "rules:\n  - id: test\n    pattern: hashlib.md5(...)\n    message: bad\n    severity: WARNING"
    r.severity = "high"
    r.enabled = True
    r.created_by = _USER_ID
    r.created_at = datetime.now(UTC)
    r.updated_at = datetime.now(UTC)
    return r


class TestValidateOpenGrepRule:
    """Test the YAML validation utility."""

    def test_valid_rule(self) -> None:
        content = "rules:\n  - id: test\n    pattern: foo(...)\n    message: bad\n    severity: WARNING"
        errors = validate_opengrep_rule(content)
        assert errors == []

    def test_missing_rules_key(self) -> None:
        errors = validate_opengrep_rule("id: test")
        assert any("Missing 'rules'" in e for e in errors)

    def test_missing_id(self) -> None:
        content = "rules:\n  - pattern: foo(...)"
        errors = validate_opengrep_rule(content)
        assert any("missing 'id'" in e for e in errors)

    def test_missing_pattern(self) -> None:
        content = "rules:\n  - id: test\n    message: bad"
        errors = validate_opengrep_rule(content)
        assert any("missing pattern" in e for e in errors)

    def test_invalid_yaml(self) -> None:
        errors = validate_opengrep_rule("{{{{invalid")
        assert any("Invalid YAML" in e for e in errors)


class TestUpload:
    """Test uploading custom rules."""

    @pytest.mark.asyncio
    async def test_upload_valid_rule(self) -> None:
        svc = CustomRuleService()
        session = AsyncMock()
        actor = _make_actor()

        with patch("app.services.custom_rule_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.upload(
                name="MD5 detector",
                description="Detect MD5",
                language="python",
                pattern_type="opengrep",
                pattern="rules:\n  - id: test\n    pattern: hashlib.md5(...)\n    message: bad\n    severity: WARNING",
                severity="high",
                actor=actor,
                session=session,
            )

        session.add.assert_called_once()
        assert result["name"] == "MD5 detector"

    @pytest.mark.asyncio
    async def test_upload_invalid_yaml_rejected(self) -> None:
        svc = CustomRuleService()
        session = AsyncMock()
        actor = _make_actor()

        with pytest.raises(ValueError, match="Invalid OpenGrep"):
            await svc.upload(
                name="Bad rule",
                description="",
                language="python",
                pattern_type="opengrep",
                pattern="not: a: valid: rule",
                severity="high",
                actor=actor,
                session=session,
            )


class TestFork:
    """Test forking built-in rules."""

    @pytest.mark.asyncio
    async def test_fork_builtin_rule(self) -> None:
        svc = CustomRuleService()
        session = AsyncMock()
        actor = _make_actor()

        with patch("app.services.custom_rule_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.fork(
                builtin_id="cbom-python-md5",
                actor=actor,
                session=session,
            )

        assert "custom" in result["name"]
        assert result["parent_rule"] == "cbom-python-md5"
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_fork_unknown_builtin_raises(self) -> None:
        svc = CustomRuleService()
        session = AsyncMock()
        actor = _make_actor()

        with pytest.raises(ValueError, match="not found"):
            await svc.fork(builtin_id="nonexistent", actor=actor, session=session)


class TestDryRun:
    """Test dry-running a rule against sample code."""

    @pytest.mark.asyncio
    async def test_dry_run_returns_matches(self) -> None:
        svc = CustomRuleService()
        rule = _make_rule()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = rule
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        result = await svc.dry_run(
            rule_id=rule.id,
            test_code="import hashlib\nh = hashlib.md5(data)",
            actor=actor,
            session=session,
        )

        assert result["match_count"] >= 1
        assert result["rule_name"] == "test-rule"


class TestDeltaSync:
    """Test delta sync for CLI synchronization."""

    @pytest.mark.asyncio
    async def test_delta_returns_newer_rules(self) -> None:
        svc = CustomRuleService()
        rule = _make_rule()

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [rule]
        mock_result.scalars.return_value = mock_scalars
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        result = await svc.delta_sync(
            since=datetime(2020, 1, 1, tzinfo=UTC),
            actor=actor,
            session=session,
        )

        assert len(result) == 1


class TestListRules:
    """Test listing with filters."""

    @pytest.mark.asyncio
    async def test_list_all_rules(self) -> None:
        svc = CustomRuleService()
        rule = _make_rule()

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [rule]
        mock_result.scalars.return_value = mock_scalars
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        result = await svc.list_rules(actor=actor, session=session)
        assert len(result) == 1


class TestRBAC:
    """Verify role enforcement."""

    @pytest.mark.asyncio
    async def test_developer_cannot_upload(self) -> None:
        svc = CustomRuleService()
        session = AsyncMock()
        actor = _make_actor(role="developer")

        with pytest.raises(PermissionError):
            await svc.upload(
                name="test",
                description="",
                language="python",
                pattern_type="opengrep",
                pattern="rules:\n  - id: t\n    pattern: x\n    message: m",
                severity="low",
                actor=actor,
                session=session,
            )

    @pytest.mark.asyncio
    async def test_sm_cannot_delete(self) -> None:
        svc = CustomRuleService()
        session = AsyncMock()
        actor = _make_actor(role="security_manager")

        with pytest.raises(PermissionError):
            await svc.delete(
                rule_id=uuid.uuid4(),
                actor=actor,
                session=session,
            )
