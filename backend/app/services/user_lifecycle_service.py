"""User lifecycle service (D9).

Handles role changes, disable/enable, and soft-delete with 30-day grace.
Implements the state machine: Active -> Disabled -> Deleted -> Purged (30d).
"""

from __future__ import annotations

import logging
import uuid as _uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import HTTPException, status
from sqlalchemy import func, select

from app.auth.roles import ROLE_DEFAULT_SCOPES, Role
from app.models.api_key import APIKey
from app.models.user import User
from app.services.audit_service import audit_service

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class UserLifecycleService:
    """User lifecycle operations: role change, disable, enable, delete."""

    # ------------------------------------------------------------------
    # Change role
    # ------------------------------------------------------------------

    async def change_role(
        self,
        *,
        target_user_id: str,
        new_role: str,
        actor_id: str,
        actor_org_id: str,
        session: AsyncSession,
    ) -> tuple[str, int]:
        """Change a user's role.

        If downgrading, revokes API keys with scopes exceeding the new role.
        Protects against removing the last Org Admin.

        Returns:
            Tuple of (old_role, revoked_key_count).

        Raises:
            HTTPException 404: If user not found.
            HTTPException 400: If this is the last OA and role is being downgraded.
            HTTPException 400: If the new role is invalid.
        """
        # Validate new role
        valid_roles = {r.value for r in Role}
        if new_role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {new_role}",
            )

        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(target_user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        old_role = user.role

        # Last OA protection
        if old_role == Role.ORG_ADMIN and new_role != Role.ORG_ADMIN:
            count_result = await session.execute(
                select(func.count()).select_from(User).where(
                    User.org_id == user.org_id,
                    User.role == Role.ORG_ADMIN,
                    User.disabled_at.is_(None),
                    User.deleted_at.is_(None),
                )
            )
            oa_count = count_result.scalar()
            if oa_count is not None and oa_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot change role of the last Org Admin",
                )

        user.role = new_role
        user.updated_at = datetime.now(UTC)

        # Revoke over-scoped API keys on downgrade
        revoked_count = 0
        new_role_enum = Role(new_role)
        new_scopes = {str(s) for s in ROLE_DEFAULT_SCOPES.get(new_role_enum, [])}

        keys_result = await session.execute(
            select(APIKey).where(
                APIKey.user_id == user.id,
                APIKey.revoked_at.is_(None),
            )
        )
        keys = keys_result.scalars().all()
        for key in keys:
            key_scopes = set(key.scopes) if isinstance(key.scopes, list) else set()
            if not key_scopes.issubset(new_scopes):
                key.revoked_at = datetime.now(UTC)
                revoked_count += 1

        await audit_service.log(
            action_type="user.role_change",
            user_id=_uuid.UUID(actor_id),
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={
                "old_role": old_role,
                "new_role": new_role,
                "revoked_keys": revoked_count,
            },
            session=session,
        )
        logger.info(
            "User role changed",
            extra={"extra_fields": {
                "target_user_id": target_user_id,
                "old_role": old_role,
                "new_role": new_role,
                "revoked_keys": revoked_count,
                "actor_id": actor_id,
                "org_id": str(user.org_id),
            }},
        )

        await session.flush()
        return old_role, revoked_count

    # ------------------------------------------------------------------
    # Disable
    # ------------------------------------------------------------------

    async def disable(
        self,
        *,
        target_user_id: str,
        actor_id: str,
        actor_org_id: str,
        session: AsyncSession,
    ) -> None:
        """Disable a user (soft-lock). Suspends their API keys.

        Raises:
            HTTPException 404: If user not found.
            HTTPException 400: If user is already disabled.
            HTTPException 400: If this is the last active OA.
        """
        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(target_user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if user.disabled_at is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already disabled",
            )

        # Last OA protection
        if user.role == Role.ORG_ADMIN:
            count_result = await session.execute(
                select(func.count()).select_from(User).where(
                    User.org_id == user.org_id,
                    User.role == Role.ORG_ADMIN,
                    User.disabled_at.is_(None),
                    User.deleted_at.is_(None),
                )
            )
            oa_count = count_result.scalar()
            if oa_count is not None and oa_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot disable the last Org Admin",
                )

        now = datetime.now(UTC)
        user.disabled_at = now
        user.is_active = False
        user.updated_at = now

        # Suspend API keys (set revoked_at — will be unset on re-enable)
        keys_result = await session.execute(
            select(APIKey).where(
                APIKey.user_id == user.id,
                APIKey.revoked_at.is_(None),
            )
        )
        for key in keys_result.scalars().all():
            key.revoked_at = now

        await audit_service.log(
            action_type="user.disable",
            user_id=_uuid.UUID(actor_id),
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"target_email": user.email},
            session=session,
        )

        logger.info(
            "User disabled",
            extra={"extra_fields": {
                "target_user_id": target_user_id,
                "actor_id": actor_id,
                "org_id": str(user.org_id),
            }},
        )

        await session.flush()

    # ------------------------------------------------------------------
    # Enable
    # ------------------------------------------------------------------

    async def enable(
        self,
        *,
        target_user_id: str,
        actor_id: str,
        actor_org_id: str,
        session: AsyncSession,
    ) -> None:
        """Re-enable a disabled user. Unsuspends their API keys.

        Raises:
            HTTPException 404: If user not found.
            HTTPException 400: If user is not disabled.
        """
        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(target_user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if user.disabled_at is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is not disabled",
            )

        now = datetime.now(UTC)
        disabled_at = user.disabled_at
        user.disabled_at = None
        user.is_active = True
        user.updated_at = now

        # Unsuspend API keys that were suspended at disable time
        keys_result = await session.execute(
            select(APIKey).where(
                APIKey.user_id == user.id,
                APIKey.revoked_at == disabled_at,
            )
        )
        for key in keys_result.scalars().all():
            key.revoked_at = None

        await audit_service.log(
            action_type="user.enable",
            user_id=_uuid.UUID(actor_id),
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"target_email": user.email},
            session=session,
        )

        logger.info(
            "User re-enabled",
            extra={"extra_fields": {
                "target_user_id": target_user_id,
                "actor_id": actor_id,
                "org_id": str(user.org_id),
            }},
        )

        await session.flush()

    # ------------------------------------------------------------------
    # Delete (soft-delete with 30-day grace)
    # ------------------------------------------------------------------

    async def delete(
        self,
        *,
        target_user_id: str,
        actor_id: str,
        actor_org_id: str,
        session: AsyncSession,
    ) -> None:
        """Soft-delete a user. Must be disabled first. 30-day grace period.

        Raises:
            HTTPException 404: If user not found.
            HTTPException 400: If user is not disabled first.
        """
        result = await session.execute(
            select(User).where(User.id == _uuid.UUID(target_user_id))
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if user.disabled_at is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must be disabled before deletion",
            )

        if user.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already scheduled for deletion",
            )

        now = datetime.now(UTC)
        user.deleted_at = now
        user.updated_at = now

        await audit_service.log(
            action_type="user.delete",
            user_id=_uuid.UUID(actor_id),
            org_id=user.org_id,
            resource_type="user",
            resource_id=user.id,
            details={"target_email": user.email, "grace_period_days": 30},
            session=session,
        )

        logger.info(
            "User soft-deleted",
            extra={"extra_fields": {
                "target_user_id": target_user_id,
                "actor_id": actor_id,
                "org_id": str(user.org_id),
                "grace_period_days": 30,
            }},
        )

        await session.flush()


# Module-level singleton
user_lifecycle_service = UserLifecycleService()
