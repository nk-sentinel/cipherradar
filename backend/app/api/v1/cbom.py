import uuid
from datetime import UTC, datetime
from enum import StrEnum

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.cbom import CBOMDiff, CBOMVersion, MergedCBOM, MergeRequest
from app.services.cbom_service import cbom_service
from app.services.scan_service import get_scan_cbom

router = APIRouter(tags=["cbom"])


class ExportFormat(StrEnum):
    CYCLONEDX = "cyclonedx"
    SARIF = "sarif"
    PDF = "pdf"


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


@router.get("/cbom/{scan_id}/export")
async def export_cbom(
    scan_id: uuid.UUID,
    format: ExportFormat = Query(ExportFormat.CYCLONEDX, description="Export format: cyclonedx, sarif, pdf"),
) -> JSONResponse:
    """Export a CBOM scan result in the requested format.

    - ``format=cyclonedx`` — CycloneDX 1.7 JSON document
    - ``format=sarif`` — SARIF 2.1.0 results document
    - ``format=pdf`` — PDF report (placeholder)
    """
    now = datetime.now(UTC).isoformat()

    if format == ExportFormat.CYCLONEDX:
        # Placeholder CycloneDX 1.7 document
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "serialNumber": f"urn:uuid:{scan_id}",
            "metadata": {
                "timestamp": now,
                "tools": [{"name": "CipherRadar", "version": "0.1.0"}],
            },
            "components": [],
        }
        return JSONResponse(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="cbom-{scan_id}.cdx.json"',
            },
        )

    if format == ExportFormat.SARIF:
        # Placeholder SARIF 2.1.0 document
        content = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CipherRadar",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/nk-sentinel/cipherradar",
                        },
                    },
                    "results": [],
                    "properties": {
                        "scanId": str(scan_id),
                        "generatedAt": now,
                    },
                },
            ],
        }
        return JSONResponse(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="cbom-{scan_id}.sarif.json"',
            },
        )

    # PDF — placeholder until full PDF generation is wired up
    return JSONResponse(
        content={
            "status": "pending",
            "message": "PDF generation for CBOM exports will be available soon.",
            "scanId": str(scan_id),
            "generatedAt": now,
        },
        headers={
            "Content-Disposition": f'attachment; filename="cbom-{scan_id}-report.json"',
        },
    )
