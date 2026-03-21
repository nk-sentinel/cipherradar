import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.finding import CodeSnippet, FindingListResponse, FindingResponse
from app.schemas.scan import CBOMResponse, ScanCreate, ScanListResponse, ScanResponse
from app.services import scan_service

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


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
) -> ScanListResponse:
    """List scans with pagination."""
    return await scan_service.list_scans(session, page=page, per_page=per_page)


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
