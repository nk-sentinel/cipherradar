"""Tests for the Jira config resolution and issue creation service (D18)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.jira_config_service import JiraConfigService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jira_config(
    *,
    scope_type: str = "group",
    scope_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    project_key: str = "SEC",
    issue_type: str = "Bug",
) -> MagicMock:
    """Build a mock JiraConfig ORM object."""
    cfg = MagicMock()
    cfg.id = uuid.uuid4()
    cfg.org_id = org_id or uuid.uuid4()
    cfg.scope_type = scope_type
    cfg.scope_id = scope_id or uuid.uuid4()
    cfg.project_key = project_key
    cfg.issue_type = issue_type
    cfg.priority_mapping = {"critical": "Highest", "high": "High"}
    cfg.custom_fields = {}
    cfg.default_assignee = None
    cfg.labels = ["crypto"]
    return cfg


def _make_finding(
    *,
    finding_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a mock Finding ORM object."""
    f = MagicMock()
    f.id = finding_id or uuid.uuid4()
    f.org_id = org_id or uuid.uuid4()
    f.project_id = project_id or uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.name = "RSA-1024"
    f.severity = "critical"
    f.quantum_status = "quantum-vulnerable"
    f.asset_type = "Key"
    f.rule_id = "cbom-java-weak-rsa"
    f.location_file = "src/crypto/KeyManager.java"
    f.location_line = 42
    f.properties = {"cwe": "CWE-326", "remediation": "Upgrade to RSA-2048"}
    return f


def _make_actor(org_id: uuid.UUID | None = None) -> MagicMock:
    """Build a mock AuthenticatedUser."""
    actor = MagicMock()
    actor.user_id = str(uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = "security_engineer"
    return actor


# ---------------------------------------------------------------------------
# resolve_config: project overrides group
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_config_project_overrides_group() -> None:
    """When a project-level config exists, it takes precedence over group."""
    service = JiraConfigService()
    session = AsyncMock()
    org_id = uuid.uuid4()
    project_id = uuid.uuid4()

    project_config = _make_jira_config(
        scope_type="project", scope_id=project_id, org_id=org_id, project_key="PROJ",
    )

    # First query: project-level config found
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = project_config
    session.execute = AsyncMock(return_value=mock_result)

    result = await service.resolve_config(
        org_id=org_id, session=session, project_id=project_id,
    )

    assert result is not None
    assert result.scope_type == "project"
    assert result.project_key == "PROJ"


# ---------------------------------------------------------------------------
# resolve_config: falls back to group
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_config_falls_back_to_group() -> None:
    """When no project-level config, falls back to the project's group config."""
    service = JiraConfigService()
    session = AsyncMock()
    org_id = uuid.uuid4()
    project_id = uuid.uuid4()
    group_id = uuid.uuid4()

    group_config = _make_jira_config(
        scope_type="group", scope_id=group_id, org_id=org_id, project_key="GRP",
    )

    # First query: no project-level config
    no_result = MagicMock()
    no_result.scalar_one_or_none.return_value = None

    # Second query: look up project's group_id
    group_id_result = MagicMock()
    group_id_result.scalar_one_or_none.return_value = group_id

    # Third query: group-level config found
    group_result = MagicMock()
    group_result.scalar_one_or_none.return_value = group_config

    session.execute = AsyncMock(
        side_effect=[no_result, group_id_result, group_result],
    )

    result = await service.resolve_config(
        org_id=org_id, session=session, project_id=project_id,
    )

    assert result is not None
    assert result.scope_type == "group"
    assert result.project_key == "GRP"


# ---------------------------------------------------------------------------
# resolve_config: returns None when unconfigured
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_config_returns_none_when_unconfigured() -> None:
    """When no config at project or group level, returns None."""
    service = JiraConfigService()
    session = AsyncMock()
    org_id = uuid.uuid4()
    project_id = uuid.uuid4()

    no_result = MagicMock()
    no_result.scalar_one_or_none.return_value = None

    session.execute = AsyncMock(return_value=no_result)

    result = await service.resolve_config(
        org_id=org_id, session=session, project_id=project_id,
    )

    assert result is None


# ---------------------------------------------------------------------------
# create_issue: builds correct payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_issue_builds_correct_payload() -> None:
    """create_issue should build a valid Jira payload from the finding."""
    service = JiraConfigService()
    session = AsyncMock()

    org_id = uuid.uuid4()
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    finding = _make_finding(finding_id=finding_id, org_id=org_id, project_id=project_id)
    config = _make_jira_config(scope_type="group", org_id=org_id, project_key="SEC")
    actor = _make_actor(org_id=org_id)

    # Mock finding lookup
    finding_result = MagicMock()
    finding_result.scalar_one_or_none.return_value = finding

    # Mock resolve_config
    with patch.object(service, "resolve_config", new_callable=AsyncMock, return_value=config):
        # Mock audit_service.log
        with patch("app.services.jira_config_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            session.execute = AsyncMock(return_value=finding_result)
            session.flush = AsyncMock()

            result = await service.create_issue(
                finding_id=finding_id, actor=actor, session=session,
            )

    assert "issue_key" in result
    assert result["issue_key"].startswith("SEC-")
    assert "issue_url" in result
    assert result["summary"].startswith("[CipherRadar] CRITICAL:")
    assert "RSA-1024" in result["summary"]


# ---------------------------------------------------------------------------
# create_issue: stores URL on finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_issue_stores_url_on_finding() -> None:
    """create_issue should store the issue URL in finding.properties."""
    service = JiraConfigService()
    session = AsyncMock()

    org_id = uuid.uuid4()
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    finding = _make_finding(finding_id=finding_id, org_id=org_id, project_id=project_id)
    config = _make_jira_config(scope_type="group", org_id=org_id, project_key="SEC")
    actor = _make_actor(org_id=org_id)

    finding_result = MagicMock()
    finding_result.scalar_one_or_none.return_value = finding

    with patch.object(service, "resolve_config", new_callable=AsyncMock, return_value=config):
        with patch("app.services.jira_config_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            session.execute = AsyncMock(return_value=finding_result)
            session.flush = AsyncMock()

            result = await service.create_issue(
                finding_id=finding_id, actor=actor, session=session,
            )

    # Verify finding.properties was updated with issue URL
    assert finding.properties["jira_issue_key"] == result["issue_key"]
    assert finding.properties["jira_issue_url"] == result["issue_url"]


# ---------------------------------------------------------------------------
# save_config: group level
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_config_group_level() -> None:
    """save_config should create a new group-level config when none exists."""
    service = JiraConfigService()
    session = AsyncMock()
    org_id = uuid.uuid4()
    group_id = uuid.uuid4()

    # No existing config
    no_result = MagicMock()
    no_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=no_result)
    session.flush = AsyncMock()

    config_data = {
        "jira_project_key": "SEC",
        "default_issue_type": "Bug",
        "priority_mapping": {"critical": "Highest"},
        "custom_fields": {},
        "default_assignee": None,
        "labels": ["crypto"],
    }

    result = await service.save_config(
        scope_type="group",
        scope_id=group_id,
        org_id=org_id,
        config_data=config_data,
        session=session,
    )

    # Verify session.add was called with a JiraConfig
    session.add.assert_called_once()
    added = session.add.call_args[0][0]
    assert added.scope_type == "group"
    assert added.scope_id == group_id
    assert added.project_key == "SEC"


# ---------------------------------------------------------------------------
# save_config: project level
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_config_project_level() -> None:
    """save_config should create a project-level config override."""
    service = JiraConfigService()
    session = AsyncMock()
    org_id = uuid.uuid4()
    project_id = uuid.uuid4()

    no_result = MagicMock()
    no_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=no_result)
    session.flush = AsyncMock()

    config_data = {
        "jira_project_key": "PROJ",
        "default_issue_type": "Task",
        "priority_mapping": {},
        "custom_fields": {"customfield_10001": "value"},
        "default_assignee": "dev@example.com",
        "labels": [],
    }

    result = await service.save_config(
        scope_type="project",
        scope_id=project_id,
        org_id=org_id,
        config_data=config_data,
        session=session,
    )

    session.add.assert_called_once()
    added = session.add.call_args[0][0]
    assert added.scope_type == "project"
    assert added.scope_id == project_id
    assert added.project_key == "PROJ"
    assert added.default_assignee == "dev@example.com"
