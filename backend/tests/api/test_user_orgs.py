"""Tests for user orgs API endpoints."""

import uuid
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.main import create_app

FAKE_USER_ID = str(uuid.uuid4())
FAKE_ORG_ID = str(uuid.uuid4())


def _make_user() -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=FAKE_USER_ID,
        org_id=FAKE_ORG_ID,
        role="developer",
        scopes=["scan:read", "cbom:read"],
    )


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# GET /api/v1/user/orgs
# ---------------------------------------------------------------------------


class TestListUserOrgs:
    @pytest.mark.asyncio
    async def test_returns_user_orgs(self, app, client: AsyncClient) -> None:
        user = _make_user()
        mock_session = AsyncMock()
        org_uuid = uuid.UUID(FAKE_ORG_ID)
        mock_result = AsyncMock()
        mock_result.fetchall.return_value = [
            (org_uuid, "nk-sentinel", "enterprise", "org_admin"),
        ]
        mock_session.execute = AsyncMock(return_value=mock_result)

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.get("/api/v1/user/orgs")

        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) == 1
        assert body["items"][0]["name"] == "nk-sentinel"
        assert body["items"][0]["plan"] == "enterprise"
        assert body["items"][0]["role"] == "org_admin"
        assert body["items"][0]["id"] == FAKE_ORG_ID

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_returns_multiple_orgs(self, app, client: AsyncClient) -> None:
        user = _make_user()
        mock_session = AsyncMock()
        org_1 = uuid.uuid4()
        org_2 = uuid.uuid4()
        mock_result = AsyncMock()
        mock_result.fetchall.return_value = [
            (org_1, "nk-sentinel", "enterprise", "org_admin"),
            (org_2, "Acme Corp", "team", "developer"),
        ]
        mock_session.execute = AsyncMock(return_value=mock_result)

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.get("/api/v1/user/orgs")

        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) == 2
        assert body["items"][0]["name"] == "nk-sentinel"
        assert body["items"][1]["name"] == "Acme Corp"
        assert body["items"][1]["role"] == "developer"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_orgs(self, app, client: AsyncClient) -> None:
        user = _make_user()
        mock_session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.fetchall.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override
        app.dependency_overrides[get_current_user] = lambda: user

        response = await client.get("/api/v1/user/orgs")

        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_no_auth_returns_401(self, app, client: AsyncClient) -> None:
        response = await client.get("/api/v1/user/orgs")
        assert response.status_code == 401
