import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.compliance import (
    ComplianceReport,
    MigrationItem,
    QuantumRiskScore,
)
from app.services.compliance_service import ComplianceService

router = APIRouter(prefix="/projects", tags=["compliance"])

_compliance = ComplianceService()


async def _get_project_findings(session: AsyncSession, project_id: uuid.UUID) -> list[Finding]:
    """Load all findings for a project. Raises 404 if the project does not exist."""
    # Verify project exists
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    if project_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Project not found")

    stmt = select(Finding).where(Finding.project_id == project_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{project_id}/compliance/nist-800-131a", response_model=ComplianceReport)
async def nist_800_131a_report(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ComplianceReport:
    """Evaluate project findings against NIST SP 800-131A Rev. 3."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.evaluate_nist_800_131a(findings)


@router.get("/{project_id}/compliance/fips-140-3", response_model=ComplianceReport)
async def fips_140_3_report(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ComplianceReport:
    """Evaluate project findings against FIPS 140-3."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.evaluate_fips_140_3(findings)


@router.get("/{project_id}/quantum-risk", response_model=QuantumRiskScore)
async def quantum_risk_score(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> QuantumRiskScore:
    """Compute quantum risk score for a project."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.compute_quantum_risk_score(findings)


@router.get("/{project_id}/migration-priority", response_model=list[MigrationItem])
async def migration_priority_queue(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> list[MigrationItem]:
    """Get prioritized migration queue for quantum-vulnerable algorithms."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.get_migration_priority_queue(findings)
