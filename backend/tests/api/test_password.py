"""Integration tests for password management API endpoints (D6, D30)."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import bcrypt as _bcrypt
import pytest

from app.auth.jwt import create_access_token
from app.auth.roles import Role

if TYPE_CHECKING:
    from httpx import AsyncClient


_TEST_USER_ID = str(uuid.uuid4())
_TEST_ORG_ID = str(uuid.uuid4())
_TEST_PASSWORD = "OldPass123!"
_TEST_HASH = _bcrypt.hashpw(_TEST_PASSWORD.encode(), _bcrypt.gensalt()).decode()


def _mock_user_obj() -> MagicMock:
    """Build a mock User model for session queries."""
    user = MagicMock()
    user.id = uuid.UUID(_TEST_USER_ID)
    user.email = "alice@example.com"
    user.hashed_password = _TEST_HASH
    user.auth_source = "local"
    user.org_id = uuid.UUID(_TEST_ORG_ID)
    return user


def _admin_token() -> str:
    return create_access_token(
        user_id=_TEST_USER_ID,
        role=str(Role.ORG_ADMIN),
        scopes=["scan:read", "scan:write"],
        org_id=_TEST_ORG_ID,
    )


def _user_token() -> str:
    return create_access_token(
        user_id=_TEST_USER_ID,
        role=str(Role.DEVELOPER),
        scopes=["scan:read"],
        org_id=_TEST_ORG_ID,
    )


class TestChangePasswordEndpoint:
    @pytest.mark.asyncio
    async def test_change_password_requires_auth(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/api/v1/auth/password",
            json={"currentPassword": "old", "newPassword": "NewPass123!"},
        )
        assert resp.status_code == 401


class TestForgotPasswordEndpoint:
    @pytest.mark.asyncio
    async def test_forgot_password_always_200(self, client: AsyncClient) -> None:
        """Forgot password should return 200 regardless of whether email exists."""
        with patch("app.api.v1.password.password_service") as mock_svc:
            mock_svc.forgot_password = AsyncMock()
            resp = await client.post(
                "/api/v1/auth/forgot-password",
                json={"email": "nobody@example.com"},
            )
        assert resp.status_code == 200


class TestResetPasswordEndpoint:
    @pytest.mark.asyncio
    async def test_reset_password_validation(self, client: AsyncClient) -> None:
        """Reset password with short password should fail validation."""
        resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": "sometoken", "newPassword": "short"},
        )
        assert resp.status_code == 422  # Pydantic validation (min_length=8)
