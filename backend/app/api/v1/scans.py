import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.schemas.finding import CodeSnippet, FindingListResponse, FindingResponse
from app.schemas.scan import (
    CBOMResponse,
    ScanCreate,
    ScanListResponse,
    ScanQueueListResponse,
    ScanQueueResponse,
    ScanResponse,
)
from app.services import scan_service
from app.services.audit_service import audit_service

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_create: ScanCreate,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Submit a new scan for a project."""
    result = await scan_service.create_scan(session, scan_create)
    await session.commit()
    return result


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Get a scan by ID."""
    return await scan_service.get_scan(session, scan_id)


@router.get("/{scan_id}/cbom", response_model=CBOMResponse)
async def get_scan_cbom(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> CBOMResponse:
    """Get the CBOM document for a completed scan."""
    return await scan_service.get_scan_cbom(session, scan_id)


@router.get("", response_model=ScanQueueListResponse)
async def list_scans(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=25, ge=1, le=100, description="Items per page"),
    status: str | None = Query(default=None, description="Filter by scan status"),
    project_id: uuid.UUID | None = Query(default=None, description="Filter by project ID"),
    trigger_type: str | None = Query(default=None, description="Filter by trigger type (manual, schedule, webhook, cli)"),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanQueueListResponse:
    """List scans with pagination, filters, and RBAC scoping (D20 #38).

    Scans are scoped to the user's organisation. Additional filters can narrow
    results by status, project, or trigger type.

    Accepts both ``per_page`` (snake_case) and ``perPage`` (camelCase) for the
    page-size parameter.
    """
    # Support camelCase query params from frontend
    camel_per_page = request.query_params.get("perPage")
    if camel_per_page is not None:
        try:
            val = int(camel_per_page)
            if 1 <= val <= 100:
                per_page = val
        except ValueError:
            pass

    if project_id is None:
        camel_project_id = request.query_params.get("projectId")
        if camel_project_id is not None:
            try:
                project_id = uuid.UUID(camel_project_id)
            except ValueError:
                pass

    # Base query scoped to user's org
    base = select(Scan).where(Scan.org_id == uuid.UUID(user.org_id))

    # Apply filters
    if status is not None:
        base = base.where(Scan.status == status)
    if project_id is not None:
        base = base.where(Scan.project_id == project_id)

    # Count total matching
    count_stmt = select(func.count()).select_from(base.subquery())
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Fetch page with project join for name
    offset = (page - 1) * per_page
    stmt = (
        base.options(joinedload(Scan.project))
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await session.execute(stmt)
    scans = result.unique().scalars().all()

    items: list[ScanQueueResponse] = []
    for s in scans:
        duration = None
        if s.started_at and s.completed_at:
            duration = (s.completed_at - s.started_at).total_seconds()
        items.append(
            ScanQueueResponse(
                id=s.id,
                project_id=s.project_id,
                project_name=s.project.name if s.project else None,
                status=s.status.value if isinstance(s.status, ScanStatus) else s.status,
                branch=s.branch,
                commit_sha=s.commit_sha,
                trigger_type=None,  # populated when trigger tracking is added
                triggered_by=None,
                findings_count=s.findings_count,
                started_at=s.started_at,
                completed_at=s.completed_at,
                created_at=s.created_at,
                duration_seconds=duration,
                environment=s.environment,
            )
        )

    return ScanQueueListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post(
    "/{scan_id}/rerun",
    response_model=ScanResponse,
    status_code=201,
    dependencies=[Depends(require_role(
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
    ))],
)
async def rerun_scan(
    scan_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    """Re-run a scan with the same configuration (D20 #37, #40).

    Clones the original scan's config (branch, policy, source type) and creates
    a new scan in queued status.
    RBAC: Org Admin, Security Manager, Security Engineer.
    """
    # Load original scan
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await session.execute(stmt)
    original = result.scalar_one_or_none()
    if original is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Create new scan cloning config
    new_scan = Scan(
        id=uuid.uuid4(),
        project_id=original.project_id,
        org_id=original.org_id,
        status=ScanStatus.QUEUED,
        branch=original.branch,
        commit_sha=original.commit_sha,
        findings_count=0,
    )
    session.add(new_scan)
    await session.flush()
    await session.refresh(new_scan)

    # Audit log
    await audit_service.log(
        action_type="scan.rerun",
        user_id=uuid.UUID(user.user_id),
        org_id=uuid.UUID(user.org_id),
        resource_type="scan",
        resource_id=new_scan.id,
        details={
            "original_scan_id": str(scan_id),
            "branch": original.branch,
        },
        session=session,
    )

    await session.commit()
    return ScanResponse.model_validate(new_scan)


def _finding_to_response(finding: Finding) -> FindingResponse:
    """Convert a Finding ORM object to a FindingResponse schema."""
    props = finding.properties or {}
    code_data = props.get("code")
    code = CodeSnippet(**code_data) if code_data else None
    return FindingResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        project_id=finding.project_id,
        severity=finding.severity,
        file=finding.location_file,
        line=finding.location_line,
        title=finding.name,
        algorithm=props.get("algorithm"),
        quantum_status=finding.quantum_status,
        detection_pass=props.get("detection_pass", 1),
        rule_id=finding.rule_id,
        confidence=finding.confidence,
        asset_type=finding.asset_type,
        code=code,
        remediation=props.get("remediation"),
    )


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def list_scan_findings(
    scan_id: uuid.UUID,
    severity: str | None = Query(default=None, description="Filter by severity (critical, high, medium, low, info)"),
    quantum_status: str | None = Query(default=None, description="Filter by quantum status (vulnerable, safe, broken, unknown)"),
    search: str | None = Query(default=None, description="Search findings by name, file, or rule ID"),
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
) -> FindingListResponse:
    """List paginated findings for a scan with optional filters."""
    # Verify scan exists
    scan_stmt = select(Scan).where(Scan.id == scan_id)
    scan_result = await session.execute(scan_stmt)
    if scan_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build base query
    base = select(Finding).where(Finding.scan_id == scan_id)

    if severity is not None:
        base = base.where(Finding.severity == severity)
    if quantum_status is not None:
        base = base.where(Finding.quantum_status == quantum_status)
    if search is not None:
        like_pattern = f"%{search}%"
        base = base.where(
            Finding.name.ilike(like_pattern)
            | Finding.location_file.ilike(like_pattern)
            | Finding.rule_id.ilike(like_pattern)
        )

    # Count total matching
    count_stmt = select(func.count()).select_from(base.subquery())
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Fetch page
    offset = (page - 1) * per_page
    stmt = base.order_by(Finding.created_at.desc()).offset(offset).limit(per_page)
    result = await session.execute(stmt)
    findings = result.scalars().all()

    return FindingListResponse(
        items=[_finding_to_response(f) for f in findings],
        total=total,
        page=page,
        per_page=per_page,
    )
