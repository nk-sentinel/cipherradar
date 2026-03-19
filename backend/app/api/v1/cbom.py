import uuid

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.cbom import CBOMDiff, CBOMVersion, MergedCBOM, MergeRequest
from app.services.cbom_service import cbom_service
from app.services.scan_service import get_scan_cbom

router = APIRouter(tags=["cbom"])


@router.get(
    "/projects/{project_id}/cbom/versions",
    response_model=list[CBOMVersion],
)
async def list_cbom_versions(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> list[CBOMVersion]:
    """List all CBOM versions for a project, ordered by version number."""
    return await cbom_service.get_versions(project_id, session)


@router.get("/cbom/diff", response_model=CBOMDiff)
async def diff_cboms(
    base: uuid.UUID = Query(..., description="Base scan ID"),
    head: uuid.UUID = Query(..., description="Head scan ID"),
    session: AsyncSession = Depends(get_session),
) -> CBOMDiff:
    """Compare two CBOM documents and return the diff."""
    return await cbom_service.diff(base, head, session)


@router.post("/cbom/merge", response_model=MergedCBOM)
async def merge_cboms(
    body: MergeRequest,
    session: AsyncSession = Depends(get_session),
) -> MergedCBOM:
    """Merge multiple CBOMs into a single portfolio-level CBOM."""
    return await cbom_service.merge(body.scan_ids, session)


@router.get("/scans/{scan_id}/cbom/download")
async def download_cbom(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    """Download the full CBOM JSON document for a scan."""
    cbom_response = await get_scan_cbom(session, scan_id)
    return JSONResponse(
        content=cbom_response.cbom_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="cbom-{scan_id}.json"',
        },
    )
