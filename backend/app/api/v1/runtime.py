"""Runtime enrichment API endpoints (ADR-028)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.project import Project
from app.schemas.runtime import (
    EnrichedFinding,
    RuntimeObservationBatch,
    RuntimeSummary,
)
from app.services.runtime_service import RuntimeService

router = APIRouter(tags=["runtime"])

_runtime = RuntimeService()

# Default org_id for observations that don't provide one.
# In production this comes from auth context.
_DEFAULT_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")


async def _verify_project(session: AsyncSession, project_id: uuid.UUID) -> Project:
    """Verify a project exists. Raises 404 if not found."""
    stmt = select(Project).where(Project.id == project_id)
    result = await session.execute(stmt)
    project = result.scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post("/runtime/enrich", status_code=201)
async def ingest_runtime_observations(
    batch: RuntimeObservationBatch,
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    """Accept runtime observations from an OTel exporter.

    Ingests a batch of TLS/cipher observations and links them to projects.
    """
    if not batch.observations:
        return {"ingested": 0}

    # Verify all referenced projects exist
    project_ids = {obs.project_id for obs in batch.observations}
    for pid in project_ids:
        await _verify_project(session, pid)

    # In production, org_id comes from API key / auth context.
    # For now, derive from the first project.
    first_project = await _verify_project(session, batch.observations[0].project_id)
    org_id = getattr(first_project, "org_id", _DEFAULT_ORG_ID)

    count = await _runtime.ingest_batch(session, batch.observations, org_id)
    return {"ingested": count}


@router.get(
    "/projects/{project_id}/runtime/summary",
    response_model=RuntimeSummary,
)
async def runtime_summary(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> RuntimeSummary:
    """Get runtime observation summary for a project."""
    await _verify_project(session, project_id)
    return await _runtime.get_runtime_summary(session, project_id)


@router.get(
    "/scans/{scan_id}/runtime/enriched",
    response_model=list[EnrichedFinding],
)
async def enriched_findings(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> list[EnrichedFinding]:
    """Get findings enriched with runtime data for a specific scan."""
    return await _runtime.get_enriched_findings(session, scan_id)
