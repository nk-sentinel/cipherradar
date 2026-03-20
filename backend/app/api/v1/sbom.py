import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.sbom import SBOMCBOMLinkResponse, SBOMUploadResponse
from app.services import sbom_service

router = APIRouter(tags=["sbom"])


@router.post("/sbom/upload", response_model=SBOMUploadResponse, status_code=201)
async def upload_sbom(
    request: Request,
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> SBOMUploadResponse:
    """Upload a CycloneDX or SPDX SBOM JSON document.

    The SBOM is parsed, components are extracted, and the document is
    stored via the CBOMStore pattern.
    """
    body = await request.body()
    result = await sbom_service.upload_sbom(session, project_id, body)
    await session.commit()
    return result


@router.get(
    "/projects/{project_id}/sbom-cbom-link",
    response_model=SBOMCBOMLinkResponse,
)
async def sbom_cbom_link(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> SBOMCBOMLinkResponse:
    """Get SBOM-to-CBOM linkage for a project.

    Matches SBOM library components to CBOM cryptographic findings.
    """
    return await sbom_service.get_sbom_cbom_links(session, project_id)
