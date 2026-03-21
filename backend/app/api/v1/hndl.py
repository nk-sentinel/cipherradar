"""HNDL (Harvest Now Decrypt Later) risk model API endpoint (ADR-032)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.hndl import HNDLRisk
from app.services.hndl_service import HNDLService

router = APIRouter(prefix="/projects", tags=["hndl"])

_hndl = HNDLService()


async def _get_project_findings(session: AsyncSession, project_id: uuid.UUID) -> list[Finding]:
    """Load all findings for a project. Raises 404 if the project does not exist."""
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    if project_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Project not found")

    stmt = select(Finding).where(Finding.project_id == project_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{project_id}/hndl-risk", response_model=HNDLRisk)
async def hndl_risk(
    project_id: uuid.UUID,
    data_classification: str = Query(
        default="internal",
        description="Data sensitivity classification: public, internal, confidential, restricted",
    ),
    session: AsyncSession = Depends(get_session),
) -> HNDLRisk:
    """Compute the HNDL risk score for a project."""
    findings = await _get_project_findings(session, project_id)
    return await _hndl.compute_risk(
        project_id=project_id,
        findings=findings,
        data_classification=data_classification,
    )
