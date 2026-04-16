"""Artifact registry CRUD service (D2).

Manages container/artifact registry configurations for organisations.

Usage::

    from app.services.artifact_registry_service import artifact_registry_service

    registries = await artifact_registry_service.list_registries(org_id, session)
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy import select

from app.models.artifact_registry import ArtifactRegistry
from app.schemas.artifact_registry import (
    RegistryCreate,
    RegistryResponse,
    RegistryTestResult,
    RegistryUpdate,
)
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

logger = logging.getLogger(__name__)

# Valid registry types
VALID_REGISTRY_TYPES = frozenset({
    "jfrog", "ecr", "gcr", "acr", "docker_hub", "harbor", "gitlab", "custom",
})


class ArtifactRegistryService:
    """CRUD operations for artifact registries."""

    async def list_registries(
        self,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> list[RegistryResponse]:
        """List all registries for an org."""
        result = await session.execute(
            select(ArtifactRegistry)
            .where(ArtifactRegistry.org_id == org_id)
            .order_by(ArtifactRegistry.name)
        )
        registries = result.scalars().all()
        return [RegistryResponse.model_validate(r) for r in registries]

    async def get_registry(
        self,
        registry_id: uuid.UUID,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> RegistryResponse:
        """Get a single registry by ID."""
        result = await session.execute(
            select(ArtifactRegistry)
            .where(ArtifactRegistry.id == registry_id)
            .where(ArtifactRegistry.org_id == org_id)
        )
        registry = result.scalar_one_or_none()
        if registry is None:
            raise HTTPException(status_code=404, detail="Registry not found")
        return RegistryResponse.model_validate(registry)

    async def create_registry(
        self,
        org_id: uuid.UUID,
        data: RegistryCreate,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> RegistryResponse:
        """Create a new artifact registry."""
        self._validate_type(data.registry_type)

        registry = ArtifactRegistry(
            org_id=org_id,
            name=data.name,
            registry_type=data.registry_type,
            url=data.url,
            auth_token_encrypted=data.auth_token_encrypted,
            enabled=data.enabled,
        )
        session.add(registry)
        await session.flush()
        await session.refresh(registry)

        await audit_service.log(
            action_type="registry.create",
            user_id=actor.user_uuid,
            org_id=org_id,
            resource_type="artifact_registry",
            resource_id=registry.id,
            details={"name": data.name, "type": data.registry_type, "url": data.url},
            session=session,
        )

        return RegistryResponse.model_validate(registry)

    async def update_registry(
        self,
        registry_id: uuid.UUID,
        org_id: uuid.UUID,
        data: RegistryUpdate,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> RegistryResponse:
        """Update an existing artifact registry."""
        result = await session.execute(
            select(ArtifactRegistry)
            .where(ArtifactRegistry.id == registry_id)
            .where(ArtifactRegistry.org_id == org_id)
        )
        registry = result.scalar_one_or_none()
        if registry is None:
            raise HTTPException(status_code=404, detail="Registry not found")

        changes: dict[str, object] = {}
        if data.name is not None:
            changes["name"] = data.name
            registry.name = data.name
        if data.registry_type is not None:
            self._validate_type(data.registry_type)
            changes["registry_type"] = data.registry_type
            registry.registry_type = data.registry_type
        if data.url is not None:
            changes["url"] = data.url
            registry.url = data.url
        if data.auth_token_encrypted is not None:
            registry.auth_token_encrypted = data.auth_token_encrypted
            changes["auth_updated"] = True
        if data.enabled is not None:
            changes["enabled"] = data.enabled
            registry.enabled = data.enabled

        await session.flush()

        await audit_service.log(
            action_type="registry.update",
            user_id=actor.user_uuid,
            org_id=org_id,
            resource_type="artifact_registry",
            resource_id=registry_id,
            details=changes,
            session=session,
        )

        return RegistryResponse.model_validate(registry)

    async def delete_registry(
        self,
        registry_id: uuid.UUID,
        org_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> None:
        """Delete an artifact registry."""
        result = await session.execute(
            select(ArtifactRegistry)
            .where(ArtifactRegistry.id == registry_id)
            .where(ArtifactRegistry.org_id == org_id)
        )
        registry = result.scalar_one_or_none()
        if registry is None:
            raise HTTPException(status_code=404, detail="Registry not found")

        await audit_service.log(
            action_type="registry.delete",
            user_id=actor.user_uuid,
            org_id=org_id,
            resource_type="artifact_registry",
            resource_id=registry_id,
            details={"name": registry.name},
            session=session,
        )

        await session.delete(registry)
        await session.flush()

    async def test_connection(
        self,
        registry_id: uuid.UUID,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> RegistryTestResult:
        """Test connectivity to a registry (mock implementation for now)."""
        result = await session.execute(
            select(ArtifactRegistry)
            .where(ArtifactRegistry.id == registry_id)
            .where(ArtifactRegistry.org_id == org_id)
        )
        registry = result.scalar_one_or_none()
        if registry is None:
            raise HTTPException(status_code=404, detail="Registry not found")

        # Mock connection test — real implementation will probe the registry
        return RegistryTestResult(
            success=True,
            message=f"Successfully connected to {registry.registry_type} registry at {registry.url}",
            latency_ms=42.0,
        )

    @staticmethod
    def _validate_type(registry_type: str) -> None:
        """Validate that the registry type is supported."""
        if registry_type not in VALID_REGISTRY_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid registry type: {registry_type}. "
                f"Valid types: {', '.join(sorted(VALID_REGISTRY_TYPES))}",
            )


# Module-level singleton
artifact_registry_service = ArtifactRegistryService()
