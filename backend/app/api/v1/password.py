"""Password management API endpoints (D6, D30).

Handles password change, admin reset, forgot-password, and token-based reset.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.password import (
    AdminResetPasswordResponse,
    ChangePasswordRequest,
    ChangePasswordResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
)
from app.services.password_service import password_service

router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# PUT /api/v1/auth/password — change own password (authenticated)
# ---------------------------------------------------------------------------


@router.put("/auth/password", response_model=ChangePasswordResponse)
async def change_password(
    body: ChangePasswordRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ChangePasswordResponse:
    """Change the current user's password. Requires current password verification."""
    await password_service.change_password(
        user_id=user.user_id,
        current_password=body.current_password,
        new_password=body.new_password,
        session=session,
        actor_org_id=user.org_id,
    )
    await session.commit()
    return ChangePasswordResponse()


# ---------------------------------------------------------------------------
# PUT /api/v1/admin/users/{id}/reset-password — admin reset (OA only)
# ---------------------------------------------------------------------------


@router.put(
    "/admin/users/{user_id}/reset-password",
    response_model=AdminResetPasswordResponse,
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def admin_reset_password(
    user_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> AdminResetPasswordResponse:
    """Reset a user's password and generate a temporary one. Org Admin only."""
    temp_password = await password_service.admin_reset_password(
        target_user_id=str(user_id),
        actor_id=user.user_id,
        actor_org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return AdminResetPasswordResponse(temp_password=temp_password)


# ---------------------------------------------------------------------------
# POST /api/v1/auth/forgot-password — public
# ---------------------------------------------------------------------------


@router.post("/auth/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    body: ForgotPasswordRequest,
    session: AsyncSession = Depends(get_session),
) -> ForgotPasswordResponse:
    """Request a password reset email. Always returns 200 to prevent enumeration."""
    await password_service.forgot_password(
        email=body.email,
        session=session,
    )
    await session.commit()
    return ForgotPasswordResponse()


# ---------------------------------------------------------------------------
# POST /api/v1/auth/reset-password — public (with token)
# ---------------------------------------------------------------------------


@router.post("/auth/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    body: ResetPasswordRequest,
    session: AsyncSession = Depends(get_session),
) -> ResetPasswordResponse:
    """Reset password using a token from the forgot-password email."""
    await password_service.reset_password(
        token=body.token,
        new_password=body.new_password,
        session=session,
    )
    await session.commit()
    return ResetPasswordResponse()
