"""Tests for admin API endpoints."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.jwt import create_access_token
from app.auth.middleware import AuthenticatedUser, get_current_user
from app.auth.roles import Role
from app.db.session import get_session
from app.main import create_app

FAKE_USER_ID = str(uuid.uuid4())
FAKE_ORG_ID = str(uuid.uuid4())


def _make_admin_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=FAKE_USER_ID,
        org_id=FAKE_ORG_ID,
        role=str(Role.ORG_ADMIN),
        scopes=["scan:read", "scan:write", "cbom:read", "project:read", "project:write", "report:read"],
    )


def _mock_session_override():
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    return _override


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# GET /api/v1/admin/settings
# ---------------------------------------------------------------------------


class TestGetSettings:
    @pytest.mark.asyncio
    async def test_get_settings_as_admin(self, app, client: AsyncClient) -> None:
        user = _make_admin_user()
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (
            uuid.UUID(FAKE_ORG_ID),
            "nk-sentinel",
            "enterprise",
            {
                "default_scan_config": {
                    "auto_scan": True,
                    "scan_on_pr": True,
                    "policy_file": "policy.cbom.yml",
                    "fail_on_severity": "high",
                }
            },
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.get("/api/v1/admin/settings")

        assert response.status_code == 200
        body = response.json()
        assert body["name"] == "nk-sentinel"
        assert body["plan"] == "enterprise"
        assert body["defaultScanConfig"]["autoScan"] is True
        assert body["defaultScanConfig"]["scanOnPr"] is True
        assert body["defaultScanConfig"]["policyFile"] == "policy.cbom.yml"
        assert body["defaultScanConfig"]["failOnSeverity"] == "high"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_get_settings_as_developer_forbidden(self, app, client_with_session: AsyncClient) -> None:
        token = create_access_token(
            user_id=FAKE_USER_ID,
            role=str(Role.DEVELOPER),
            scopes=["scan:read"],
            org_id=FAKE_ORG_ID,
        )
        response = await client_with_session.get(
            "/api/v1/admin/settings",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_get_settings_no_auth_returns_401(self, app, client_with_session: AsyncClient) -> None:
        response = await client_with_session.get("/api/v1/admin/settings")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/v1/admin/settings
# ---------------------------------------------------------------------------


class TestUpdateSettings:
    @pytest.mark.asyncio
    async def test_update_settings_as_admin(self, app, client: AsyncClient) -> None:
        user = _make_admin_user()
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (
            uuid.UUID(FAKE_ORG_ID),
            "nk-sentinel",
            "enterprise",
            {"default_scan_config": {"auto_scan": False}},
        )
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.put(
            "/api/v1/admin/settings",
            json={
                "name": "updated-org",
                "defaultScanConfig": {
                    "autoScan": True,
                    "scanOnPr": True,
                    "policyFile": "new-policy.yml",
                    "failOnSeverity": "critical",
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["name"] == "updated-org"
        assert body["defaultScanConfig"]["autoScan"] is True
        assert body["defaultScanConfig"]["policyFile"] == "new-policy.yml"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_update_settings_as_security_manager(self, app, client: AsyncClient) -> None:
        user = AuthenticatedUser(
            user_id=FAKE_USER_ID,
            org_id=FAKE_ORG_ID,
            role=str(Role.SECURITY_MANAGER),
            scopes=["scan:read", "scan:write"],
        )
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (
            uuid.UUID(FAKE_ORG_ID),
            "nk-sentinel",
            "team",
            {},
        )
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.put(
            "/api/v1/admin/settings",
            json={"plan": "enterprise"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["plan"] == "enterprise"

        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/admin/users
# ---------------------------------------------------------------------------


class TestListUsers:
    @pytest.mark.asyncio
    async def test_list_users(self, app, client: AsyncClient) -> None:
        user = _make_admin_user()
        mock_session = AsyncMock()
        user_id_1 = uuid.uuid4()
        user_id_2 = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            (user_id_1, "alice@example.com", "org_admin", True, "2026-01-01T00:00:00Z"),
            (user_id_2, "bob@example.com", "developer", False, "2026-01-02T00:00:00Z"),
        ]
        mock_session.execute = AsyncMock(return_value=mock_result)

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.get("/api/v1/admin/users")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2
        assert body["items"][0]["email"] == "alice@example.com"
        assert body["items"][0]["role"] == "org_admin"
        assert body["items"][0]["status"] == "active"
        assert body["items"][1]["status"] == "invited"

        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/invite
# ---------------------------------------------------------------------------


class TestInviteUser:
    @pytest.mark.asyncio
    async def test_invite_user(self, app, client: AsyncClient) -> None:
        user = _make_admin_user()
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.post(
            "/api/v1/admin/users/invite",
            json={"email": "newuser@example.com", "role": "developer", "name": "New User"},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "newuser@example.com"
        assert body["role"] == "developer"
        assert body["status"] == "invited"
        assert body["inviteToken"].startswith("inv_")

        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/admin/integrations
# ---------------------------------------------------------------------------


class TestListIntegrations:
    @pytest.mark.asyncio
    async def test_list_integrations(self, app, client: AsyncClient) -> None:
        user = _make_admin_user()
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.get("/api/v1/admin/integrations")

        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) == 5

        types = {item["type"] for item in body["items"]}
        assert "github" in types
        assert "gitlab" in types
        assert "bitbucket" in types
        assert "jira" in types
        assert "teams" in types

        # Verify structure of a connected integration
        github = next(i for i in body["items"] if i["type"] == "github")
        assert github["status"] == "connected"
        assert github["connectedAt"] is not None
        assert github["label"] == "GitHub"

        # Verify disconnected integration
        bitbucket = next(i for i in body["items"] if i["type"] == "bitbucket")
        assert bitbucket["status"] == "disconnected"
        assert bitbucket["connectedAt"] is None

        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/admin/audit-log
# ---------------------------------------------------------------------------


class TestAuditLog:
    @pytest.mark.asyncio
    async def test_audit_log_returns_entries(self, app, client: AsyncClient) -> None:
        from unittest.mock import patch

        user = _make_admin_user()
        mock_session = AsyncMock()

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        mock_items = [
            {
                "id": str(uuid.uuid4()),
                "timestamp": "2026-03-01T10:00:00Z",
                "user_id": str(uuid.uuid4()),
                "action_type": action,
                "resource_type": "scan",
                "resource_id": str(uuid.uuid4()),
                "details": {},
                "ip_address": "127.0.0.1",
            }
            for action in [
                "scan.completed", "user.login", "policy.updated",
                "scan.started", "user.login", "scan.completed",
                "policy.updated", "user.login", "scan.completed",
                "user.login",
            ]
        ]

        with patch(
            "app.services.audit_log_query_service.audit_log_query_service.query",
            new_callable=AsyncMock,
            return_value={"items": mock_items, "total": 10, "page": 1, "per_page": 25},
        ):
            response = await client.get("/api/v1/admin/audit-log")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 10
        assert len(body["items"]) == 10

        # Check structure of first entry (camelCase keys)
        entry = body["items"][0]
        assert "id" in entry
        assert "timestamp" in entry
        assert "actionType" in entry
        assert "resourceType" in entry

        # Check action types are valid
        actions = {item["actionType"] for item in body["items"]}
        assert "scan.completed" in actions
        assert "user.login" in actions
        assert "policy.updated" in actions

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_audit_log_developer_forbidden(self, app, client_with_session: AsyncClient) -> None:
        token = create_access_token(
            user_id=FAKE_USER_ID,
            role=str(Role.DEVELOPER),
            scopes=["scan:read"],
            org_id=FAKE_ORG_ID,
        )
        response = await client_with_session.get(
            "/api/v1/admin/audit-log",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
