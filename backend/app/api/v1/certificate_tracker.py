"""Certificate Tracker API — paginated certificate expiry tracking (D23).

Route: GET /api/v1/portfolio/certificates
Roles: all authenticated users.
"""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.schemas.certificate_tracker import CertificateTrackerResponse
from app.services.certificate_tracker_service import certificate_tracker_service
from app.services.group_service import get_accessible_project_ids

router = APIRouter(prefix="/portfolio", tags=["portfolio"])


@router.get("/certificates", response_model=CertificateTrackerResponse)
async def list_certificates(
    status_color: str | None = Query(None, description="Filter by status: green, amber, red, black"),
    project_id: uuid.UUID | None = Query(None, description="Filter by project ID"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(25, ge=1, le=100, description="Items per page"),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CertificateTrackerResponse:
    """List certificates with expiry status, paginated and filterable.

    Extracts certificate findings from the database, computes days remaining
    and status color (green >90d, amber 30-90d, red <30d, black expired).
    Group-scoped: only returns certificates from accessible projects.
    """
    project_ids = await get_accessible_project_ids(session, user)
    return await certificate_tracker_service.list_certificates(
        session=session,
        org_id=user.org_id,
        project_ids=project_ids,
        status_color=status_color,
        project_id=project_id,
        page=page,
        per_page=per_page,
    )
