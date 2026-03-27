"""Pydantic request/response models for user lifecycle endpoints (D9)."""

from __future__ import annotations

from pydantic import Field

from app.schemas.base import CamelCaseModel


# ---------------------------------------------------------------------------
# Role change
# ---------------------------------------------------------------------------


class ChangeRoleRequest(CamelCaseModel):
    """Request body for changing a user's role."""

    role: str = Field(min_length=1, max_length=50)


class ChangeRoleResponse(CamelCaseModel):
    """Response after changing a user's role."""

    user_id: str
    old_role: str
    new_role: str
    revoked_keys: int = Field(
        default=0, description="Number of API keys revoked due to scope downgrade"
    )


# ---------------------------------------------------------------------------
# Disable / Enable
# ---------------------------------------------------------------------------


class UserStatusResponse(CamelCaseModel):
    """Response after enabling or disabling a user."""

    user_id: str
    status: str  # "disabled" or "active"
    message: str


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


class DeleteUserResponse(CamelCaseModel):
    """Response after soft-deleting a user."""

    user_id: str
    message: str = "User scheduled for deletion (30-day grace period)"
