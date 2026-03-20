from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user_or_api_key
from app.db.session import get_session
from app.schemas.scan_upload import ScanUploadResponse
from app.services.scan_upload_service import process_scan_upload

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/upload", response_model=ScanUploadResponse, status_code=201)
async def upload_scan(
    request: Request,
    project_name: str = Query(..., min_length=1, max_length=255),
    group_path: str | None = Query(default=None, max_length=1024),
    branch: str | None = Query(default=None, max_length=255),
    commit_sha: str | None = Query(default=None, max_length=40),
    user: AuthenticatedUser = Depends(get_current_user_or_api_key),
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    """Upload CycloneDX CBOM JSON to create a scan with findings (ADR-025).

    Authentication: API key (Bearer token) or JWT.
    Project resolution: find by name within user's org, auto-create if project:write scope.
    Group resolution: find group by path, fallback to default with X-CipherRadar-Warning header.
    """
    body = await request.body()

    result, warnings = await process_scan_upload(
        session=session,
        user=user,
        project_name=project_name,
        group_path=group_path,
        branch=branch,
        commit_sha=commit_sha,
        cbom_raw=body,
    )
    await session.commit()

    response_data = ScanUploadResponse(
        scan_id=result["scan_id"],
        project_id=result["project_id"],
        project_name=result["project_name"],
        group_path=result.get("group_path"),
        findings_count=result["findings_count"],
        status=result["status"],
        warnings=warnings,
        created_at=result["created_at"],
    )

    headers = {}
    if warnings:
        headers["X-CipherRadar-Warning"] = "; ".join(warnings)

    return JSONResponse(
        content=response_data.model_dump(mode="json"),
        status_code=201,
        headers=headers,
    )
