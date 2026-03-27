"""Tests for forgot password email flow (D30).

Covers email sending via mock SMTP, graceful failure when SMTP is not
configured, and token expiration.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.user import User
from app.services.password_service import PasswordService, _reset_tokens


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG_ID = uuid.uuid4()


def _make_user(
    *,
    email: str = "alice@example.com",
    auth_source: str = "local",
) -> MagicMock:
    u = MagicMock(spec=User)
    u.id = uuid.uuid4()
    u.email = email
    u.auth_source = auth_source
    u.org_id = _ORG_ID
    return u


def _mock_session(user: MagicMock | None) -> AsyncMock:
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = user
    session.execute = AsyncMock(return_value=result_mock)
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestForgotPasswordEmail:
    @pytest.mark.asyncio
    async def test_sends_email_mock(self) -> None:
        """Verify that the email send function is called with correct args."""
        service = PasswordService()
        service.clear_reset_tokens()
        user = _make_user()
        session = _mock_session(user)
        mock_send = AsyncMock()

        with (
            patch("app.services.password_service._send_email_fn", mock_send),
            patch("app.services.password_service.audit_service") as mock_audit,
        ):
            mock_audit.log = AsyncMock()
            await service.forgot_password(email=user.email, session=session)

        mock_send.assert_called_once()
        call_args = mock_send.call_args
        assert call_args[0][0] == user.email  # to
        assert "Reset" in call_args[0][1]  # subject contains Reset
        assert "reset-password" in call_args[0][2]  # body contains link
        service.clear_reset_tokens()

    @pytest.mark.asyncio
    async def test_graceful_if_no_smtp(self) -> None:
        """When no SMTP is configured (_send_email_fn is None), should not raise."""
        service = PasswordService()
        service.clear_reset_tokens()
        user = _make_user()
        session = _mock_session(user)

        with (
            patch("app.services.password_service._send_email_fn", None),
            patch("app.services.password_service.audit_service") as mock_audit,
        ):
            mock_audit.log = AsyncMock()
            # Should not raise
            await service.forgot_password(email=user.email, session=session)

        # Token should still be generated even if email fails
        assert len(_reset_tokens) == 1
        service.clear_reset_tokens()

    @pytest.mark.asyncio
    async def test_token_expires(self) -> None:
        """Expired tokens should be rejected during password reset."""
        import secrets

        service = PasswordService()
        service.clear_reset_tokens()
        user = _make_user()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        _reset_tokens[token_hash] = {
            "user_id": str(user.id),
            "expires_at": datetime.now(UTC) - timedelta(minutes=1),  # expired
        }

        session = _mock_session(user)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.reset_password(
                token=raw_token,
                new_password="NewPassword123!",
                session=session,
            )

        assert exc_info.value.status_code == 400
        assert "expired" in exc_info.value.detail.lower()
        service.clear_reset_tokens()
