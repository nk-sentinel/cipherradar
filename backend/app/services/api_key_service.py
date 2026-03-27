"""API key management service (D7).

Handles creation (returns raw key once, stores hash), listing (prefix only),
revocation, and scope capping by user role.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import HTTPException, status
from sqlalchemy import select

from app.auth.api_keys import generate_api_key
from app.auth.roles import ROLE_DEFAULT_SCOPES, Role
from app.models.api_key import APIKey
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class ApiKeyService:
    """API key CRUD operations."""

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create(
        self,
        *,
        name: str,
        scopes: list[str],
        expires_in_days: int | None,
        user_id: str,
        user_role: str,
        org_id: str,
        session: AsyncSession,
    ) -> tuple[APIKey, str]:
        """Create a new API key.

        Returns:
            Tuple of (APIKey model, plaintext_key).
            The plaintext key is returned once — only the hash is stored.

        Raises:
            HTTPException 400: If requested scopes exceed user's role scopes.
        """
        # Cap scopes to user's role
        role_enum = Role(user_role) if user_role in [r.value for r in Role] else Role.DEVELOPER
        allowed_scopes = {str(s) for s in ROLE_DEFAULT_SCOPES.get(role_enum, [])}
        capped_scopes = [s for s in scopes if s in allowed_scopes]

        if not capped_scopes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid scopes for your role",
            )

        plaintext_key, key_hash = generate_api_key()
        key_prefix = plaintext_key[:12]

        expires_at = None
        if expires_in_days is not None:
            expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)

        api_key = APIKey(
            id=_uuid.uuid4(),
            org_id=_uuid.UUID(org_id),
            user_id=_uuid.UUID(user_id),
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=capped_scopes,
            expires_at=expires_at,
        )
        session.add(api_key)

        await audit_service.log(
            action_type="api_key.create",
            user_id=_uuid.UUID(user_id),
            org_id=_uuid.UUID(org_id),
            resource_type="api_key",
            resource_id=api_key.id,
            details={"name": name, "scopes": capped_scopes, "key_prefix": key_prefix},
            session=session,
        )
        await session.flush()
        return api_key, plaintext_key

    # ------------------------------------------------------------------
    # List own keys
    # ------------------------------------------------------------------

    async def list_own(
        self,
        *,
        user_id: str,
        session: AsyncSession,
    ) -> list[APIKey]:
        """List API keys for the current user (prefix only, no plaintext)."""
        result = await session.execute(
            select(APIKey)
            .where(
                APIKey.user_id == _uuid.UUID(user_id),
                APIKey.revoked_at.is_(None),
            )
            .order_by(APIKey.created_at.desc())
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # List all org keys (OA/SM)
    # ------------------------------------------------------------------

    async def list_all_org(
        self,
        *,
        org_id: str,
        session: AsyncSession,
    ) -> list[APIKey]:
        """List all API keys in the organisation. OA/SM only."""
        result = await session.execute(
            select(APIKey)
            .where(APIKey.org_id == _uuid.UUID(org_id))
            .order_by(APIKey.created_at.desc())
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Revoke own
    # ------------------------------------------------------------------

    async def revoke_own(
        self,
        *,
        key_id: str,
        user_id: str,
        org_id: str,
        session: AsyncSession,
    ) -> None:
        """Revoke one of the current user's API keys.

        Raises:
            HTTPException 404: If key not found or not owned by user.
        """
        result = await session.execute(
            select(APIKey).where(
                APIKey.id == _uuid.UUID(key_id),
                APIKey.user_id == _uuid.UUID(user_id),
            )
        )
        key = result.scalar_one_or_none()
        if key is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

        key.revoked_at = datetime.now(UTC)

        await audit_service.log(
            action_type="api_key.revoke",
            user_id=_uuid.UUID(user_id),
            org_id=_uuid.UUID(org_id),
            resource_type="api_key",
            resource_id=key.id,
            details={"name": key.name, "key_prefix": key.key_prefix},
            session=session,
        )
        await session.flush()

    # ------------------------------------------------------------------
    # Revoke any (OA)
    # ------------------------------------------------------------------

    async def revoke_any(
        self,
        *,
        key_id: str,
        org_id: str,
        actor_id: str,
        session: AsyncSession,
    ) -> None:
        """Revoke any API key in the organisation. OA only.

        Raises:
            HTTPException 404: If key not found in this org.
        """
        result = await session.execute(
            select(APIKey).where(
                APIKey.id == _uuid.UUID(key_id),
                APIKey.org_id == _uuid.UUID(org_id),
            )
        )
        key = result.scalar_one_or_none()
        if key is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

        key.revoked_at = datetime.now(UTC)

        await audit_service.log(
            action_type="api_key.admin_revoke",
            user_id=_uuid.UUID(actor_id),
            org_id=_uuid.UUID(org_id),
            resource_type="api_key",
            resource_id=key.id,
            details={"name": key.name, "owner": str(key.user_id)},
            session=session,
        )
        await session.flush()


# Module-level singleton
api_key_service = ApiKeyService()
