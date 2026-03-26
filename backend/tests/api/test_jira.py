"""API-level tests for Jira integration routes (D18).

Tests RBAC enforcement and route wiring. Service logic is tested separately
in tests/services/test_jira_config_service.py.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.jwt import create_access_token
from app.auth.roles import ROLE_DEFAULT_SCOPES, Role
from app.db.session import get_session
from app.main import create_app

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

ORG_ID = str(uuid.uuid4())
USER_ID = str(uuid.uuid4())
GROUP_ID = uuid.uuid4()
PROJECT_ID = uuid.uuid4()
FINDING_ID = uuid.uuid4()


def _token_for_role(role: Role, org_id: str = ORG_ID) -> str:
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role, [])]
    return create_access_token(
        user_id=USER_ID,
        role=str(role),
        scopes=scopes,
        org_id=org_id,
    )


def _make_jira_config_mock(scope_type: str = "group") -> MagicMock:
    cfg = MagicMock()
    cfg.id = uuid.uuid4()
    cfg.project_key = "SEC"
    cfg.issue_type = "Bug"
    cfg.priority_mapping = {}
    cfg.custom_fields = {}
    cfg.default_assignee = None
    cfg.labels = ["crypto"]
    cfg.scope_type = scope_type
    return cfg


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# POST /api/v1/findings/{finding_id}/jira — create issue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_jira_issue_returns_issue(app, client: AsyncClient) -> None:
    """POST /findings/{id}/jira should create a Jira issue and return it."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    mock_result = {
        "issue_key": "SEC-A1B2",
        "issue_url": "https://jira.example.com/browse/SEC-A1B2",
        "summary": "[CipherRadar] CRITICAL: RSA-1024",
    }

    with patch(
        "app.api.v1.jira.jira_config_service.create_issue",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        token = _token_for_role(Role.SECURITY_ENGINEER)
        resp = await client.post(
            f"/api/v1/findings/{FINDING_ID}/jira",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["issueKey"] == "SEC-A1B2"
    assert body["issueUrl"] == "https://jira.example.com/browse/SEC-A1B2"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# RBAC: Developer cannot create Jira issue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rbac_dev_cannot_create_jira_issue(app, client: AsyncClient) -> None:
    """Developer role should be denied access to create Jira issues."""
    token = _token_for_role(Role.DEVELOPER)
    resp = await client.post(
        f"/api/v1/findings/{FINDING_ID}/jira",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# RBAC: Developer cannot save config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rbac_dev_cannot_save_config(app, client: AsyncClient) -> None:
    """Developer role should be denied access to save Jira config."""
    token = _token_for_role(Role.DEVELOPER)
    resp = await client.put(
        f"/api/v1/groups/{GROUP_ID}/jira-config",
        json={
            "jiraProjectKey": "SEC",
            "defaultIssueType": "Bug",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/v1/groups/{group_id}/jira-config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_group_jira_config(app, client: AsyncClient) -> None:
    """GET /groups/{id}/jira-config should return the group config."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    config = _make_jira_config_mock("group")

    with patch(
        "app.api.v1.jira.jira_config_service.resolve_config",
        new_callable=AsyncMock,
        return_value=config,
    ):
        token = _token_for_role(Role.ORG_ADMIN)
        resp = await client.get(
            f"/api/v1/groups/{GROUP_ID}/jira-config",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["jiraProjectKey"] == "SEC"
    assert body["scope"] == "group"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/groups/{group_id}/jira-config — 404
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_group_jira_config_not_found(app, client: AsyncClient) -> None:
    """GET /groups/{id}/jira-config should return 404 when unconfigured."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch(
        "app.api.v1.jira.jira_config_service.resolve_config",
        new_callable=AsyncMock,
        return_value=None,
    ):
        token = _token_for_role(Role.ORG_ADMIN)
        resp = await client.get(
            f"/api/v1/groups/{GROUP_ID}/jira-config",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 404

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# PUT /api/v1/groups/{group_id}/jira-config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_group_jira_config(app, client: AsyncClient) -> None:
    """PUT /groups/{id}/jira-config should save and return the config."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    config = _make_jira_config_mock("group")

    with patch(
        "app.api.v1.jira.jira_config_service.save_config",
        new_callable=AsyncMock,
        return_value=config,
    ):
        token = _token_for_role(Role.SECURITY_MANAGER)
        resp = await client.put(
            f"/api/v1/groups/{GROUP_ID}/jira-config",
            json={
                "jiraProjectKey": "SEC",
                "defaultIssueType": "Bug",
                "priorityMapping": {},
                "customFields": {},
                "labels": ["crypto"],
            },
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["jiraProjectKey"] == "SEC"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{project_id}/jira-config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_project_jira_config(app, client: AsyncClient) -> None:
    """GET /projects/{id}/jira-config should return the resolved config."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    config = _make_jira_config_mock("project")

    with patch(
        "app.api.v1.jira.jira_config_service.resolve_config",
        new_callable=AsyncMock,
        return_value=config,
    ):
        token = _token_for_role(Role.TEAM_MANAGER)
        resp = await client.get(
            f"/api/v1/projects/{PROJECT_ID}/jira-config",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["scope"] == "project"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# PUT /api/v1/projects/{project_id}/jira-config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_project_jira_config(app, client: AsyncClient) -> None:
    """PUT /projects/{id}/jira-config should save and return the config."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    config = _make_jira_config_mock("project")

    with patch(
        "app.api.v1.jira.jira_config_service.save_config",
        new_callable=AsyncMock,
        return_value=config,
    ):
        token = _token_for_role(Role.ORG_ADMIN)
        resp = await client.put(
            f"/api/v1/projects/{PROJECT_ID}/jira-config",
            json={
                "jiraProjectKey": "PROJ",
                "defaultIssueType": "Task",
            },
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["jiraProjectKey"] == "SEC"  # from mock

    app.dependency_overrides.clear()
