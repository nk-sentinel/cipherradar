import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.models.organisation import Organisation
from app.models.project import Group, Project
from app.models.scan import Scan, ScanStatus
from app.schemas.base import CamelCaseModel
from app.schemas.scan import ScanListResponse, ScanResponse

router = APIRouter(tags=["projects"])
repos_router = APIRouter(tags=["repos"])


# ---------------------------------------------------------------------------
# Schemas for project list endpoint
# ---------------------------------------------------------------------------


class ProjectResponse(CamelCaseModel):
    """Response schema for a single project in a list."""

    id: uuid.UUID
    name: str
    type: str = "repository"
    group_id: uuid.UUID
    group_name: str | None = None
    org_id: uuid.UUID
    org_path: str | None = None
    git_url: str | None = None
    provider: str | None = None
    last_scan_at: datetime | None = None
    findings_count: int = 0

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class ProjectListResponse(CamelCaseModel):
    """Paginated list of projects."""

    items: list[ProjectResponse]
    total: int
    page: int
    per_page: int


# ---------------------------------------------------------------------------
# GET /projects — list all projects for the user's org
# ---------------------------------------------------------------------------


@router.get("/projects", response_model=ProjectListResponse)
async def list_projects(
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ProjectListResponse:
    """List all projects for the authenticated user's organisation (paginated)."""
    org_id = user.required_org_uuid

    # Count total projects in org
    count_stmt = (
        select(func.count())
        .select_from(Project)
        .where(Project.org_id == org_id)
    )
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Fetch page
    offset = (page - 1) * per_page
    stmt = (
        select(Project)
        .where(Project.org_id == org_id)
        .order_by(Project.name)
        .offset(offset)
        .limit(per_page)
    )
    result = await session.execute(stmt)
    projects = result.scalars().all()

    # Prefetch group names
    group_ids = {p.group_id for p in projects}
    group_map: dict[uuid.UUID, str] = {}
    if group_ids:
        grp_result = await session.execute(
            select(Group.id, Group.name).where(Group.id.in_(group_ids))
        )
        group_map = {row[0]: row[1] for row in grp_result.fetchall()}

    # For each project, get latest scan date and total findings count
    items: list[ProjectResponse] = []
    for p in projects:
        # Latest scan date
        last_scan_stmt = (
            select(func.max(Scan.completed_at))
            .where(Scan.project_id == p.id)
            .where(Scan.status == ScanStatus.COMPLETED)
        )
        last_scan_result = await session.execute(last_scan_stmt)
        last_scan_at = last_scan_result.scalar_one_or_none()

        # Findings count from latest completed scan
        findings_stmt = (
            select(func.coalesce(func.sum(Scan.findings_count), 0))
            .where(Scan.project_id == p.id)
            .where(Scan.status == ScanStatus.COMPLETED)
        )
        findings_result = await session.execute(findings_stmt)
        findings_count = findings_result.scalar_one()

        grp_name = group_map.get(p.group_id)
        items.append(
            ProjectResponse(
                id=p.id,
                name=p.name,
                type=p.type,
                group_id=p.group_id,
                group_name=grp_name,
                org_id=p.org_id,
                org_path=f"{grp_name}/{p.name}" if grp_name else p.name,
                git_url=p.git_url,
                provider=p.provider,
                last_scan_at=last_scan_at,
                findings_count=findings_count,
            )
        )

    return ProjectListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


# ---------------------------------------------------------------------------
# GET /projects/{project_id} — single project detail
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ProjectResponse:
    """Get a single project by ID (must belong to the user's org)."""
    org_id = user.required_org_uuid

    stmt = select(Project).where(Project.id == project_id, Project.org_id == org_id)
    result = await session.execute(stmt)
    project = result.scalar_one_or_none()

    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    # Group name
    grp_result = await session.execute(
        select(Group.name).where(Group.id == project.group_id)
    )
    grp_name = grp_result.scalar_one_or_none()

    # Latest scan date
    last_scan_stmt = (
        select(func.max(Scan.completed_at))
        .where(Scan.project_id == project.id)
        .where(Scan.status == ScanStatus.COMPLETED)
    )
    last_scan_at = (await session.execute(last_scan_stmt)).scalar_one_or_none()

    # Findings count
    from app.models.finding import Finding

    findings_stmt = (
        select(func.count())
        .select_from(Finding)
        .where(Finding.project_id == project.id)
    )
    findings_count = (await session.execute(findings_stmt)).scalar_one()

    return ProjectResponse(
        id=project.id,
        name=project.name,
        type=project.type,
        group_id=project.group_id,
        group_name=grp_name,
        org_id=project.org_id,
        org_path=f"{grp_name}/{project.name}" if grp_name else project.name,
        git_url=project.git_url,
        provider=project.provider,
        last_scan_at=last_scan_at,
        findings_count=findings_count,
    )


async def _compute_is_stale(
    project_id: uuid.UUID,
    org_id: uuid.UUID,
    session: AsyncSession,
) -> bool | None:
    """Compute whether a project's last scan is stale (D20 #40).

    Returns True if the most recent completed scan is older than the org's
    stale_scan_threshold_days. Returns None if there are no completed scans.
    """
    # Get org threshold
    org_result = await session.execute(
        select(Organisation.stale_scan_threshold_days).where(Organisation.id == org_id)
    )
    threshold = org_result.scalar_one_or_none()
    if threshold is None:
        return None

    # Get last completed scan date
    last_scan_result = await session.execute(
        select(func.max(Scan.completed_at))
        .where(Scan.project_id == project_id)
        .where(Scan.status == ScanStatus.COMPLETED)
    )
    last_scan_at = last_scan_result.scalar_one_or_none()
    if last_scan_at is None:
        return None

    age_days = (datetime.now(timezone.utc) - last_scan_at).days
    return age_days > threshold


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
