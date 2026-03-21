"""Integration tests for the auth API endpoints."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import bcrypt as _bcrypt
import pytest

from app.api.v1 import auth as auth_module
from app.auth.jwt import create_access_token, create_refresh_token
from app.auth.roles import Role, Scope

if TYPE_CHECKING:
    from httpx import AsyncClient

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

_TEST_USER_ID = str(uuid.uuid4())
_TEST_PASSWORD = "s3cureP@ss!"
_TEST_HASH = _bcrypt.hashpw(_TEST_PASSWORD.encode(), _bcrypt.gensalt()).decode()

_MOCK_USER: dict = {
    "id": _TEST_USER_ID,
    "email": "alice@example.com",
    "hashed_password": _TEST_HASH,
    "role": "org_admin",
    "is_active": True,
}


@pytest.fixture(autouse=True)
def _patch_user_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wire up a mock user-lookup so login works without a database."""

    async def _lookup(email: str) -> dict | None:
        if email == _MOCK_USER["email"]:
            return _MOCK_USER
        return None

    monkeypatch.setattr(auth_module, "_user_by_email", _lookup)


@pytest.fixture(autouse=True)
def _patch_api_key_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wire up a no-op API key store."""
    monkeypatch.setattr(auth_module, "_store_api_key", AsyncMock())


# -----------------------------------------------------------------------
# POST /api/v1/auth/login
# -----------------------------------------------------------------------


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_valid_credentials(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": _TEST_PASSWORD},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "accessToken" in body
        assert "refreshToken" in body
        assert body["tokenType"] == "bearer"
        assert body["expiresIn"] == 15 * 60

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_unknown_email(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "any"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
        inactive_user = {**_MOCK_USER, "is_active": False}

        async def _lookup(email: str) -> dict | None:
            if email == inactive_user["email"]:
                return inactive_user
            return None

        monkeypatch.setattr(auth_module, "_user_by_email", _lookup)

        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": _TEST_PASSWORD},
        )
        assert resp.status_code == 401


# -----------------------------------------------------------------------
# POST /api/v1/auth/refresh
# -----------------------------------------------------------------------


class TestRefresh:
    @pytest.mark.asyncio
    async def test_refresh_valid_token(self, client: AsyncClient) -> None:
        refresh = create_refresh_token(user_id=_TEST_USER_ID)
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert resp.status_code == 200
        body = resp.json()
        assert "accessToken" in body
        assert "refreshToken" in body

    @pytest.mark.asyncio
    async def test_refresh_with_access_token_fails(self, client: AsyncClient) -> None:
        access = create_access_token(user_id=_TEST_USER_ID, role="developer", scopes=[])
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": access})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_with_garbage_token_fails(self, client: AsyncClient) -> None:
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": "garbage"})
        assert resp.status_code == 401


# -----------------------------------------------------------------------
# GET /api/v1/auth/me
# -----------------------------------------------------------------------


class TestMe:
    @pytest.mark.asyncio
    async def test_me_with_valid_token(self, client: AsyncClient) -> None:
        token = create_access_token(
            user_id=_TEST_USER_ID,
            role="org_admin",
            scopes=["scan:read", "scan:write"],
        )
        resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["userId"] == _TEST_USER_ID
        assert body["role"] == "org_admin"
        assert body["scopes"] == ["scan:read", "scan:write"]
        assert body["authMethod"] == "jwt"

    @pytest.mark.asyncio
    async def test_me_without_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401


# -----------------------------------------------------------------------
# POST /api/v1/auth/api-keys
# -----------------------------------------------------------------------


class TestApiKeys:
    @pytest.mark.asyncio
    async def test_create_api_key_as_admin(self, client: AsyncClient) -> None:
        token = create_access_token(
            user_id=_TEST_USER_ID,
            role=str(Role.ORG_ADMIN),
            scopes=[str(s) for s in Scope],
            org_id=str(uuid.uuid4()),
        )
        resp = await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "ci-key", "scopes": ["scan:read", "scan:write"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "ci-key"
        assert body["key"].startswith("cbom_sk_")
        assert body["scopes"] == ["scan:read", "scan:write"]

    @pytest.mark.asyncio
    async def test_create_api_key_as_developer_forbidden(self, client: AsyncClient) -> None:
        token = create_access_token(
            user_id=_TEST_USER_ID,
            role=str(Role.DEVELOPER),
            scopes=["scan:read"],
        )
        resp = await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "my-key", "scopes": ["scan:read"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_create_api_key_without_auth(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "my-key", "scopes": ["scan:read"]},
        )
        assert resp.status_code == 401
