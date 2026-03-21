"""Tests for assets API endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.main import create_app

FAKE_USER_ID = str(uuid.uuid4())
FAKE_ORG_ID = str(uuid.uuid4())
FAKE_PROJECT_ID = uuid.uuid4()
FAKE_FINDING_ID_1 = uuid.uuid4()
FAKE_FINDING_ID_2 = uuid.uuid4()


def _make_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=FAKE_USER_ID,
        org_id=FAKE_ORG_ID,
        role="security_manager",
        scopes=["scan:read", "cbom:read", "report:read"],
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
# GET /api/v1/assets — list, pagination, search
# ---------------------------------------------------------------------------


class TestListAssets:
    @pytest.mark.asyncio
    async def test_list_assets_empty_when_no_projects(self, app, client: AsyncClient) -> None:
        user = _make_user()
        app.dependency_overrides[get_session] = _mock_session_override()
        app.dependency_overrides[get_current_user] = lambda: user

        with patch(
            "app.api.v1.assets.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[],
        ):
            response = await client.get("/api/v1/assets")

        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["page"] == 1
        assert body["pageSize"] == 20

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_list_assets_returns_items(self, app, client: AsyncClient) -> None:
        user = _make_user()
        mock_session = AsyncMock()

        # Mock count query result
        mock_count_result = AsyncMock()
        mock_count_result.scalar.return_value = 2

        # Mock data query result
        mock_data_result = AsyncMock()
        mock_data_result.fetchall.return_value = [
            (FAKE_FINDING_ID_1, "AES-256", "algorithm", "src/crypto.py", 42, "safe", {"compliance": "compliant"}, "payment-service"),
            (FAKE_FINDING_ID_2, "RSA-2048", "algorithm", "src/auth.go", 15, "vulnerable", {"compliance": "non_compliant"}, "auth-api"),
        ]

        # execute is called twice: once for count, once for data
        mock_session.execute = AsyncMock(side_effect=[mock_count_result, mock_data_result])

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        with patch(
            "app.api.v1.assets.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[FAKE_PROJECT_ID],
        ):
            response = await client.get("/api/v1/assets")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2

        # Verify first item structure
        item = body["items"][0]
        assert item["name"] == "AES-256"
        assert item["type"] == "algorithm"
        assert item["language"] == "Python"
        assert item["repo"] == "payment-service"
        assert item["location"] == "src/crypto.py:42"
        assert item["quantumStatus"] == "safe"
        assert item["compliance"] == "compliant"

        # Verify second item
        item2 = body["items"][1]
        assert item2["language"] == "Go"
        assert item2["quantumStatus"] == "vulnerable"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_list_assets_pagination(self, app, client: AsyncClient) -> None:
        user = _make_user()
        mock_session = AsyncMock()

        mock_count_result = AsyncMock()
        mock_count_result.scalar.return_value = 50

        mock_data_result = AsyncMock()
        mock_data_result.fetchall.return_value = [
            (FAKE_FINDING_ID_1, "SHA-256", "algorithm", "lib/hash.js", 10, "safe", {}, "web-app"),
        ]

        mock_session.execute = AsyncMock(side_effect=[mock_count_result, mock_data_result])

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        with patch(
            "app.api.v1.assets.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[FAKE_PROJECT_ID],
        ):
            response = await client.get("/api/v1/assets?page=3&pageSize=10")

        assert response.status_code == 200
        body = response.json()
        assert body["page"] == 3
        assert body["pageSize"] == 10
        assert body["total"] == 50

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_list_assets_search_filter(self, app, client: AsyncClient) -> None:
        user = _make_user()
        mock_session = AsyncMock()

        mock_count_result = AsyncMock()
        mock_count_result.scalar.return_value = 1

        mock_data_result = AsyncMock()
        mock_data_result.fetchall.return_value = [
            (FAKE_FINDING_ID_1, "AES-256-GCM", "algorithm", "src/encrypt.py", 5, "safe", {}, "crypto-lib"),
        ]

        mock_session.execute = AsyncMock(side_effect=[mock_count_result, mock_data_result])

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        with patch(
            "app.api.v1.assets.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[FAKE_PROJECT_ID],
        ):
            response = await client.get("/api/v1/assets?search=AES")

        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) == 1
        assert "AES" in body["items"][0]["name"]

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_list_assets_no_auth_returns_401(self, app, client: AsyncClient) -> None:
        response = await client.get("/api/v1/assets")
        assert response.status_code == 401
