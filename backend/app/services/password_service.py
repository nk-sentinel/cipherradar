"""Password management service (D6, D30).

Handles password changes, admin resets, forgot-password token flow,
and token-based password reset.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid as _uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import bcrypt as _bcrypt_lib
from fastapi import HTTPException, status
from sqlalchemy import select, update

from app.models.user import User
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# In-memory reset token store. In production this would be a DB table.
# Maps token_hash -> {user_id, expires_at}
_reset_tokens: dict[str, dict] = {}

# SMTP send callback — set by the application startup or tests
_send_email_fn = None  # async (to, subject, html_body) -> None


def set_send_email(fn) -> None:  # noqa: ANN001, ANN201
    """Register async email sender: ``async (to, subject, html_body) -> None``."""
    global _send_email_fn  # noqa: PLW0603
    _send_email_fn = fn


class PasswordService:
    """Password management operations."""

    # ------------------------------------------------------------------
    # Change password (authenticated user)
    # ------------------------------------------------------------------

    async def change_password(
        self,
        *,
        user_id: str,
        current_password: str,
        new_password: str,
        session: AsyncSession,
        actor_org_id: str = "",
    ) -> None:
        """Change the password for the current user.

        Raises:
            HTTPException 400: If user is not local auth or current password wrong.
            HTTPException 404: If user not found.
        """
        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if user.auth_source != "local":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password change is only available for local accounts",
            )

        if not _bcrypt_lib.checkpw(current_password.encode(), user.hashed_password.encode()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        user.hashed_password = _bcrypt_lib.hashpw(
            new_password.encode(), _bcrypt_lib.gensalt()
        ).decode()
        user.updated_at = datetime.now(UTC)

        await audit_service.log(
            action_type="user.password_change",
            user_id=user.id,
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"method": "self_change"},
            session=session,
        )
        await session.flush()

    # ------------------------------------------------------------------
    # Admin reset password (OA only)
    # ------------------------------------------------------------------

    async def admin_reset_password(
        self,
        *,
        target_user_id: str,
        actor_id: str,
        actor_org_id: str,
        session: AsyncSession,
    ) -> str:
        """Generate a temporary password for a user. OA only.

        Returns:
            The temporary password (shown to admin once).

        Raises:
            HTTPException 404: If target user not found.
            HTTPException 400: If target user is not local auth.
        """
        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(target_user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if user.auth_source != "local":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset is only available for local accounts",
            )

        temp_password = secrets.token_urlsafe(16)
        user.hashed_password = _bcrypt_lib.hashpw(
            temp_password.encode(), _bcrypt_lib.gensalt()
        ).decode()
        user.updated_at = datetime.now(UTC)

        await audit_service.log(
            action_type="user.admin_password_reset",
            user_id=_uuid.UUID(actor_id),
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"target_user": target_user_id},
            session=session,
        )
        await session.flush()
        return temp_password

    # ------------------------------------------------------------------
    # Forgot password (public)
    # ------------------------------------------------------------------

    async def forgot_password(
        self,
        *,
        email: str,
        session: AsyncSession,
    ) -> None:
        """Generate a reset token and send it via email.

        Always returns successfully to prevent email enumeration.
        """
        result = await session.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()

        # If user doesn't exist or is not local, silently return
        if user is None or user.auth_source != "local":
            return

        # Generate token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        _reset_tokens[token_hash] = {
            "user_id": str(user.id),
            "expires_at": expires_at,
        }

        await audit_service.log(
            action_type="user.forgot_password",
            user_id=user.id,
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"email": email},
            session=session,
        )
        await session.flush()

        # Send email (gracefully handle missing SMTP)
        if _send_email_fn is not None:
            try:
                reset_link = f"https://app.cipherradar.io/reset-password?token={raw_token}"
                html_body = _render_reset_email(reset_link, user.email)
                await _send_email_fn(email, "CipherRadar — Reset Your Password", html_body)
            except Exception:  # noqa: BLE001
                # Gracefully handle SMTP failure — don't expose to user
                pass

    # ------------------------------------------------------------------
    # Reset password (public, with token)
    # ------------------------------------------------------------------

    async def reset_password(
        self,
        *,
        token: str,
        new_password: str,
        session: AsyncSession,
    ) -> None:
        """Reset a user's password using a valid reset token.

        Raises:
            HTTPException 400: If token is invalid or expired.
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        token_record = _reset_tokens.get(token_hash)

        if token_record is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        if datetime.now(UTC) > token_record["expires_at"]:
            # Clean up expired token
            _reset_tokens.pop(token_hash, None)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        user_id = token_record["user_id"]
        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        user.hashed_password = _bcrypt_lib.hashpw(
            new_password.encode(), _bcrypt_lib.gensalt()
        ).decode()
        user.updated_at = datetime.now(UTC)

        # Invalidate the token
        _reset_tokens.pop(token_hash, None)

        await audit_service.log(
            action_type="user.password_reset",
            user_id=user.id,
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"method": "token_reset"},
            session=session,
        )
        await session.flush()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def clear_reset_tokens(self) -> None:
        """Clear all stored reset tokens (for testing)."""
        _reset_tokens.clear()


def _render_reset_email(reset_link: str, email: str) -> str:
    """Render the password reset email HTML."""
    try:
        import os

        from jinja2 import Environment, FileSystemLoader

        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        template = env.get_template("reset-password-email.html")
        return template.render(reset_link=reset_link, email=email)
    except Exception:  # noqa: BLE001
        # Fallback to basic HTML if template loading fails
        return (
            f"<html><body>"
            f"<h2>Password Reset</h2>"
            f"<p>Click <a href='{reset_link}'>here</a> to reset your password.</p>"
            f"<p>This link expires in 1 hour.</p>"
            f"</body></html>"
        )


# Module-level singleton
password_service = PasswordService()
