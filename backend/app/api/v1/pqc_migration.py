"""PQC Migration Progress API — post-quantum readiness tracking (D23).

Route: GET /api/v1/portfolio/pqc-migration
Roles: all authenticated users.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.schemas.pqc_migration import PQCMigrationResponse
from app.services.group_service import get_accessible_project_ids
from app.services.pqc_migration_service import pqc_migration_service

router = APIRouter(prefix="/portfolio", tags=["portfolio"])


@router.get("/pqc-migration", response_model=PQCMigrationResponse)
async def get_pqc_migration_progress(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> PQCMigrationResponse:
    """Get PQC migration progress for the organisation.

    Returns an overview of quantum-vulnerable vs quantum-safe findings,
    per-algorithm-family migration progress, and a list of lagging projects.
    Group-scoped: only returns data from accessible projects.
    """
    project_ids = await get_accessible_project_ids(session, user)
    return await pqc_migration_service.get_migration_progress(
        session=session,
        org_id=user.org_id,
        project_ids=project_ids,
    )
