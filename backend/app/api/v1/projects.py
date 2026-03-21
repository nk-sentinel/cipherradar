import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanListResponse, ScanResponse

router = APIRouter(tags=["projects"])
repos_router = APIRouter(tags=["repos"])


async def _list_project_scans(
    project_id: uuid.UUID,
    page: int,
    per_page: int,
    session: AsyncSession,
) -> ScanListResponse:
    """Shared logic for listing scans for a project."""
    # Verify project exists
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    if project_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Project not found")

    # Count total
    count_stmt = select(func.count()).select_from(Scan).where(Scan.project_id == project_id)
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Fetch page
    offset = (page - 1) * per_page
    stmt = (
        select(Scan)
        .where(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await session.execute(stmt)
    scans = result.scalars().all()

    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


async def _trigger_project_scan(
    project_id: uuid.UUID,
    session: AsyncSession,
) -> ScanResponse:
    """Shared logic for triggering a new scan for a project."""
    # Verify project exists and get org_id
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    project = project_result.scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    scan = Scan(
        id=uuid.uuid4(),
        project_id=project_id,
        org_id=project.org_id,
        status=ScanStatus.QUEUED,
        findings_count=0,
    )
    session.add(scan)
    await session.flush()
    await session.refresh(scan)
    await session.commit()
    return ScanResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# /projects/{project_id}/scans
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}/scans", response_model=ScanListResponse)
async def list_project_scans(
    project_id: uuid.UUID,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
) -> ScanListResponse:
    """List scans for a specific project (paginated)."""
    return await _list_project_scans(project_id, page, per_page, session)


@router.post("/projects/{project_id}/scans/trigger", response_model=ScanResponse, status_code=201)
async def trigger_project_scan(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Trigger a new scan for a project. Creates a scan record with status=queued."""
    return await _trigger_project_scan(project_id, session)


# ---------------------------------------------------------------------------
# /repos/{project_id}/scans — alias routes for frontend compatibility
# ---------------------------------------------------------------------------


@repos_router.get("/repos/{project_id}/scans", response_model=ScanListResponse)
async def list_repo_scans(
    project_id: uuid.UUID,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
) -> ScanListResponse:
    """List scans for a repo (alias for /projects/{project_id}/scans)."""
    return await _list_project_scans(project_id, page, per_page, session)


@repos_router.post("/repos/{project_id}/scans/trigger", response_model=ScanResponse, status_code=201)
async def trigger_repo_scan(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Trigger a scan for a repo (alias for /projects/{project_id}/scans/trigger)."""
    return await _trigger_project_scan(project_id, session)
