from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from app.models.scan import Scan, ScanStatus
from app.schemas.scan import CBOMResponse, ScanCreate, ScanListResponse, ScanResponse

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.cbom import CBOMDocument


async def create_scan(session: AsyncSession, scan_create: ScanCreate) -> ScanResponse:
    """Create a new scan record with status=queued."""
    scan = Scan(
        id=uuid.uuid4(),
        project_id=scan_create.project_id,
        status=ScanStatus.QUEUED,
        branch=scan_create.branch,
        commit_sha=scan_create.commit_sha,
        findings_count=0,
    )
    session.add(scan)
    await session.flush()
    await session.refresh(scan)
    return ScanResponse.model_validate(scan)


async def get_scan(session: AsyncSession, scan_id: uuid.UUID) -> ScanResponse:
    """Get a scan by ID. Raises 404 if not found."""
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.model_validate(scan)


async def list_scans(session: AsyncSession, page: int = 1, per_page: int = 20) -> ScanListResponse:
    """Return a paginated list of scans."""
    # Count total
    count_stmt = select(func.count()).select_from(Scan)
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Fetch page
    offset = (page - 1) * per_page
    stmt = select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(per_page)
    result = await session.execute(stmt)
    scans = result.scalars().all()

    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


async def get_scan_cbom(session: AsyncSession, scan_id: uuid.UUID) -> CBOMResponse:
    """Get the CBOM document for a scan. Raises 404 if scan or CBOM not found."""
    stmt = select(Scan).where(Scan.id == scan_id).options(joinedload(Scan.cbom_document))
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    cbom_doc: CBOMDocument | None = scan.cbom_document
    if cbom_doc is None:
        raise HTTPException(status_code=404, detail="CBOM not found for this scan")

    cbom_json = cbom_doc.cbom_json or {}
    components = cbom_json.get("components", [])

    return CBOMResponse(
        scan_id=scan_id,
        spec_version=cbom_doc.spec_version,
        serial_number=cbom_doc.serial_number,
        components_count=len(components),
        cbom_json=cbom_json,
    )
