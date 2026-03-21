"""Cryptographic Agility Score API endpoint (ADR-031)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.agility import AgilityScore
from app.services.agility_service import AgilityService

router = APIRouter(prefix="/projects", tags=["agility"])

_agility = AgilityService()


async def _get_project_findings(session: AsyncSession, project_id: uuid.UUID) -> list[Finding]:
    """Load all findings for a project. Raises 404 if the project does not exist."""
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    if project_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Project not found")

    stmt = select(Finding).where(Finding.project_id == project_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{project_id}/agility-score", response_model=AgilityScore)
async def agility_score(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> AgilityScore:
    """Compute the cryptographic agility score for a project."""
    findings = await _get_project_findings(session, project_id)
    return await _agility.compute_score(project_id, findings)
