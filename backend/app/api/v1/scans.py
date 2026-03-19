import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
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
