"""Tests for password management service (D6, D30)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import bcrypt as _bcrypt
import pytest

from app.models.user import User
from app.services.password_service import PasswordService, _reset_tokens


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG_ID = uuid.uuid4()


def _make_user(
    *,
    password: str = "OldPass123!",
    auth_source: str = "local",
    org_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a mock User ORM object."""
    u = MagicMock(spec=User)
    u.id = uuid.uuid4()
    u.email = "test@example.com"
    u.hashed_password = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()
    u.auth_source = auth_source
    u.org_id = org_id or _ORG_ID
    u.updated_at = datetime.now(UTC)
    return u


def _mock_session(user: MagicMock | None) -> AsyncMock:
    """Build an AsyncMock session returning the given user from execute."""
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute = AsyncMock(return_value=result_mock)
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChangePassword:
    @pytest.mark.asyncio
    async def test_change_password_success(self) -> None:
        service = PasswordService()
        user = _make_user(password="OldPass123!")
        session = _mock_session(user)

        with patch("app.services.password_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.change_password(
                user_id=str(user.id),
                current_password="OldPass123!",
                new_password="NewPass456!",
                session=session,
            )

        # Verify password was actually updated
        assert _bcrypt.checkpw(b"NewPass456!", user.hashed_password.encode())

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self) -> None:
        service = PasswordService()
        user = _make_user(password="OldPass123!")
        session = _mock_session(user)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.change_password(
                user_id=str(user.id),
                current_password="WrongPassword!",
                new_password="NewPass456!",
                session=session,
            )
        assert exc_info.value.status_code == 400
        assert "incorrect" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_change_password_non_local_blocked(self) -> None:
        service = PasswordService()
        user = _make_user(auth_source="saml")
        session = _mock_session(user)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.change_password(
                user_id=str(user.id),
                current_password="anything",
                new_password="NewPass456!",
                session=session,
            )
        assert exc_info.value.status_code == 400
        assert "local" in exc_info.value.detail.lower()


class TestAdminResetPassword:
    @pytest.mark.asyncio
    async def test_admin_reset_generates_temp_password(self) -> None:
        service = PasswordService()
        user = _make_user()
        session = _mock_session(user)

        with patch("app.services.password_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            temp_pw = await service.admin_reset_password(
                target_user_id=str(user.id),
                actor_id=str(uuid.uuid4()),
                actor_org_id=str(_ORG_ID),
                session=session,
            )

        # Temp password is returned and user password updated
        assert len(temp_pw) > 0
        assert _bcrypt.checkpw(temp_pw.encode(), user.hashed_password.encode())


class TestForgotPassword:
    @pytest.mark.asyncio
    async def test_forgot_password_generates_token(self) -> None:
        service = PasswordService()
        service.clear_reset_tokens()
        user = _make_user()
        session = _mock_session(user)

        with patch("app.services.password_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.forgot_password(email=user.email, session=session)

        # A token should have been stored
        assert len(_reset_tokens) == 1
        service.clear_reset_tokens()


class TestResetPassword:
    @pytest.mark.asyncio
    async def test_reset_password_valid_token(self) -> None:
        service = PasswordService()
        service.clear_reset_tokens()
        user = _make_user()

        # Manually create a reset token
        import secrets

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        _reset_tokens[token_hash] = {
            "user_id": str(user.id),
            "expires_at": datetime.now(UTC) + timedelta(hours=1),
        }

        session = _mock_session(user)
        with patch("app.services.password_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.reset_password(
                token=raw_token,
                new_password="BrandNew789!",
                session=session,
            )

        assert _bcrypt.checkpw(b"BrandNew789!", user.hashed_password.encode())
        assert len(_reset_tokens) == 0  # token consumed
        service.clear_reset_tokens()

    @pytest.mark.asyncio
    async def test_reset_password_expired_token(self) -> None:
        service = PasswordService()
        service.clear_reset_tokens()
        user = _make_user()

        import secrets

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        _reset_tokens[token_hash] = {
            "user_id": str(user.id),
            "expires_at": datetime.now(UTC) - timedelta(hours=1),  # expired
        }

        session = _mock_session(user)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.reset_password(
                token=raw_token,
                new_password="BrandNew789!",
                session=session,
            )
        assert exc_info.value.status_code == 400
        service.clear_reset_tokens()

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(self) -> None:
        service = PasswordService()
        service.clear_reset_tokens()
        session = _mock_session(None)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.reset_password(
                token="nonexistent-token",
                new_password="BrandNew789!",
                session=session,
            )
        assert exc_info.value.status_code == 400
        service.clear_reset_tokens()
