"""Pydantic request/response models for password management endpoints (D6, D30)."""

from __future__ import annotations

from pydantic import Field

from app.schemas.base import CamelCaseModel


# ---------------------------------------------------------------------------
# Change password (authenticated user)
# ---------------------------------------------------------------------------


class ChangePasswordRequest(CamelCaseModel):
    """Request body for changing the current user's password."""

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)


class ChangePasswordResponse(CamelCaseModel):
    """Response after successful password change."""

    message: str = "Password changed successfully"


# ---------------------------------------------------------------------------
# Admin reset password
# ---------------------------------------------------------------------------


class AdminResetPasswordResponse(CamelCaseModel):
    """Response after admin resets a user's password."""

    temp_password: str
    message: str = "Temporary password generated"


# ---------------------------------------------------------------------------
# Forgot password (public)
# ---------------------------------------------------------------------------


class ForgotPasswordRequest(CamelCaseModel):
    """Request body for forgot-password flow."""

    email: str = Field(min_length=1, max_length=320)


class ForgotPasswordResponse(CamelCaseModel):
    """Response after forgot-password request (always succeeds to prevent enumeration)."""

    message: str = "If the email is registered, a reset link has been sent"


# ---------------------------------------------------------------------------
# Reset password (public, with token)
# ---------------------------------------------------------------------------


class ResetPasswordRequest(CamelCaseModel):
    """Request body for resetting password with a token."""

    token: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)


class ResetPasswordResponse(CamelCaseModel):
    """Response after successful password reset."""

    message: str = "Password has been reset successfully"
