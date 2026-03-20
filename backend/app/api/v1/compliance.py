import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.compliance import (
    ComplianceReport,
    ComplianceTrendResponse,
    EvidenceReport,
    GapReport,
    MigrationItem,
    QuantumRiskScore,
)
from app.services.compliance_service import ComplianceService

router = APIRouter(prefix="/projects", tags=["compliance"])

# Secondary router for non-project-scoped endpoints (e.g. trends)
trends_router = APIRouter(prefix="/compliance", tags=["compliance"])

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


@router.get("/{project_id}/compliance/pci-dss", response_model=ComplianceReport)
async def pci_dss_v4_report(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ComplianceReport:
    """Evaluate project findings against PCI-DSS v4.0."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.evaluate_pci_dss_v4(findings)


@router.get("/{project_id}/compliance/cnsa-2", response_model=ComplianceReport)
async def cnsa_2_report(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ComplianceReport:
    """Evaluate project findings against NSA CNSA 2.0."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.evaluate_cnsa_2(findings)


@router.get("/{project_id}/compliance/iso-27001", response_model=EvidenceReport)
async def iso_27001_report(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> EvidenceReport:
    """Evaluate project findings against ISO 27001 A.8.24 evidence checklist."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.evaluate_iso_27001_a8_24(findings)


@router.get("/{project_id}/compliance/eu-cra", response_model=GapReport)
async def eu_cra_report(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> GapReport:
    """Evaluate project findings against EU CRA Annex I requirements."""
    findings = await _get_project_findings(session, project_id)
    return await _compliance.evaluate_eu_cra(findings)


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


# ---------------------------------------------------------------------------
# Compliance trending endpoint
# ---------------------------------------------------------------------------


@trends_router.get("/trends", response_model=ComplianceTrendResponse)
async def compliance_trends(
    framework: str = Query(..., description="Framework identifier (e.g. pci-dss, cnsa-2, nist-800-131a, fips-140-3)"),
    period: str = Query(default="30d", description="Time period (e.g. 7d, 30d, 90d)"),
    project_id: uuid.UUID | None = Query(default=None, description="Optional project filter"),
    session: AsyncSession = Depends(get_session),
) -> ComplianceTrendResponse:
    """Get compliance score trends over time.

    Reads from the compliance_scores TimescaleDB hypertable.
    """
    from app.services.compliance_trending import get_compliance_trends

    return await get_compliance_trends(session, framework, period, project_id)
