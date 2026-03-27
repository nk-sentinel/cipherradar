"""Scan provenance and environment promotion API routes (D21).

Provides endpoints for scan provenance retrieval, scan promotion between
environments, and environment stage management.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.scan_provenance import (
    EnvironmentStageCreate,
    EnvironmentStageResponse,
    PromoteRequest,
    ProvenanceResponse,
)
from app.services.scan_provenance_service import scan_provenance_service

router = APIRouter(tags=["scan-provenance"])


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@router.get(
    "/scans/{scan_id}/provenance",
    response_model=ProvenanceResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
        Role.COMPLIANCE_AUDITOR,
    ))],
)
async def get_scan_provenance(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ProvenanceResponse:
    """Get provenance data for a scan (artifact origin, environment, promotion history)."""
    return await scan_provenance_service.get_provenance(scan_id, session)


# ---------------------------------------------------------------------------
# Promotion
# ---------------------------------------------------------------------------


@router.post(
    "/scans/promote",
    response_model=ProvenanceResponse,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
    ))],
)
async def promote_scan(
    body: PromoteRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ProvenanceResponse:
    """Promote a scan from one environment to another (D21).

    Demotes any existing scan in the target environment for the same project.
    RBAC: Org Admin, Security Manager, Security Engineer.
    """
    result = await scan_provenance_service.promote(
        scan_id=body.scan_id,
        from_env=body.from_env,
        to_env=body.to_env,
        actor=user,
        session=session,
    )
    await session.commit()
    return result


# ---------------------------------------------------------------------------
# Environment stages (admin)
# ---------------------------------------------------------------------------


@router.get(
    "/admin/environments",
    response_model=list[EnvironmentStageResponse],
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def get_environments(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[EnvironmentStageResponse]:
    """List all configured environment stages for the org."""
    return await scan_provenance_service.get_environments(
        org_id=uuid.UUID(user.org_id),
        session=session,
    )


@router.put(
    "/admin/environments",
    response_model=list[EnvironmentStageResponse],
    dependencies=[Depends(require_role(Role.ORG_ADMIN))],
)
async def update_environments(
    body: list[EnvironmentStageCreate],
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[EnvironmentStageResponse]:
    """Replace all environment stages for the org."""
    result = await scan_provenance_service.save_environments(
        org_id=uuid.UUID(user.org_id),
        stages=body,
        actor=user,
        session=session,
    )
    await session.commit()
    return result
