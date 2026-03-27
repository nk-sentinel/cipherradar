"""Artifact registry CRUD API routes (D2).

Provides admin endpoints for managing container/artifact registry
configurations. GET requires OA or SM. Mutations require OA only.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.artifact_registry import (
    RegistryCreate,
    RegistryResponse,
    RegistryTestResult,
    RegistryUpdate,
)
from app.services.artifact_registry_service import artifact_registry_service

router = APIRouter(tags=["artifact-registries"])


# ---------------------------------------------------------------------------
# Read: OA, SM
# ---------------------------------------------------------------------------


@router.get(
    "/admin/registries",
    response_model=list[RegistryResponse],
    dependencies=[Depends(require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER))],
)
async def list_registries(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[RegistryResponse]:
    """List all artifact registries for the org."""
    return await artifact_registry_service.list_registries(
        org_id=uuid.UUID(user.org_id),
        session=session,
    )


@router.get(
    "/admin/registries/{registry_id}",
    response_model=RegistryResponse,
    dependencies=[Depends(require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER))],
)
async def get_registry(
    registry_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> RegistryResponse:
    """Get a single artifact registry by ID."""
    return await artifact_registry_service.get_registry(
        registry_id=registry_id,
        org_id=uuid.UUID(user.org_id),
        session=session,
    )


# ---------------------------------------------------------------------------
# Mutations: OA only
# ---------------------------------------------------------------------------


@router.post(
    "/admin/registries",
    response_model=RegistryResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def create_registry(
    body: RegistryCreate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> RegistryResponse:
    """Create a new artifact registry. RBAC: Org Admin only."""
    result = await artifact_registry_service.create_registry(
        org_id=uuid.UUID(user.org_id),
        data=body,
        actor=user,
        session=session,
    )
    await session.commit()
    return result


@router.put(
    "/admin/registries/{registry_id}",
    response_model=RegistryResponse,
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def update_registry(
    registry_id: uuid.UUID,
    body: RegistryUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> RegistryResponse:
    """Update an artifact registry. RBAC: Org Admin only."""
    result = await artifact_registry_service.update_registry(
        registry_id=registry_id,
        org_id=uuid.UUID(user.org_id),
        data=body,
        actor=user,
        session=session,
    )
    await session.commit()
    return result


@router.delete(
    "/admin/registries/{registry_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def delete_registry(
    registry_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Delete an artifact registry. RBAC: Org Admin only."""
    await artifact_registry_service.delete_registry(
        registry_id=registry_id,
        org_id=uuid.UUID(user.org_id),
        actor=user,
        session=session,
    )
    await session.commit()


# ---------------------------------------------------------------------------
# Test connection: OA, SM
# ---------------------------------------------------------------------------


@router.post(
    "/admin/registries/{registry_id}/test",
    response_model=RegistryTestResult,
    dependencies=[Depends(require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER))],
)
async def test_registry_connection(
    registry_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> RegistryTestResult:
    """Test connectivity to a registry."""
    return await artifact_registry_service.test_connection(
        registry_id=registry_id,
        org_id=uuid.UUID(user.org_id),
        session=session,
    )
