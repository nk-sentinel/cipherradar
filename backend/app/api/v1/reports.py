"""Report generation API: PDF, HTML, and CSV reports for scan results."""

import uuid
from enum import StrEnum

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.db.session import get_session
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.services import report_service

router = APIRouter(tags=["reports"])


class ReportFormat(StrEnum):
    PDF = "pdf"
    HTML = "html"
    CSV = "csv"


class ReportType(StrEnum):
    QUANTUM_READINESS = "quantum-readiness"
    COMPLIANCE_GAP = "compliance-gap"
    FINDINGS_SUMMARY = "findings-summary"


async def _assemble_scan_data(scan_id: uuid.UUID, session: AsyncSession) -> dict:
    """Load scan + findings and assemble the data dict needed for report generation."""
    # Load the scan
    stmt = select(Scan).where(Scan.id == scan_id).options(joinedload(Scan.cbom_document))
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan is not completed")

    # Load findings
    findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
    findings_result = await session.execute(findings_stmt)
    findings = findings_result.scalars().all()

    findings_dicts = [
        {
            "name": f.name,
            "severity": f.severity,
            "confidence": f.confidence,
            "quantum_status": f.quantum_status,
            "asset_type": f.asset_type,
            "location_file": f.location_file,
            "location_line": f.location_line,
            "rule_id": f.rule_id,
        }
        for f in findings
    ]

    # Build quantum risk and compliance data from findings
    from app.services.compliance_service import ComplianceService

    compliance_svc = ComplianceService()
    quantum_risk = await compliance_svc.compute_quantum_risk_score(findings)
    nist_report = await compliance_svc.evaluate_nist_800_131a(findings)
    fips_report = await compliance_svc.evaluate_fips_140_3(findings)

    return {
        "scan_id": str(scan_id),
        "findings": findings_dicts,
        "quantum_risk": {
            "score": quantum_risk.score,
            "vulnerable_count": quantum_risk.vulnerable_count,
            "safe_count": quantum_risk.safe_count,
            "broken_count": quantum_risk.broken_count,
            "migration_items": [item.model_dump() for item in quantum_risk.migration_items],
        },
        "compliance": [
            {
                "framework": nist_report.framework,
                "score": nist_report.score,
                "compliant_count": nist_report.compliant_count,
                "non_compliant_count": nist_report.non_compliant_count,
                "items": [item.model_dump() for item in nist_report.items],
            },
            {
                "framework": fips_report.framework,
                "score": fips_report.score,
                "compliant_count": fips_report.compliant_count,
                "non_compliant_count": fips_report.non_compliant_count,
                "items": [item.model_dump() for item in fips_report.items],
            },
        ],
    }


@router.get("/scans/{scan_id}/reports")
async def get_report(
    scan_id: uuid.UUID,
    format: ReportFormat = Query(ReportFormat.PDF, description="Report format: pdf, html, csv"),
    type: ReportType = Query(ReportType.FINDINGS_SUMMARY, description="Report type"),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Generate and download a report for a scan.

    - ``format=pdf&type=quantum-readiness`` — PDF quantum readiness report
    - ``format=html&type=compliance-gap`` — HTML compliance gap report
    - ``format=csv`` — CSV export of all findings (type is ignored)
    """
    scan_data = await _assemble_scan_data(scan_id, session)

    if format == ReportFormat.CSV:
        content = await report_service.generate_csv_report(str(scan_id), scan_data)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
        )

    if format == ReportFormat.HTML:
        content = await report_service.generate_html_report(str(scan_id), type.value, scan_data)
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f'inline; filename="report-{scan_id}.html"'},
        )

    # PDF
    pdf_bytes = await report_service.generate_pdf_report(str(scan_id), type.value, scan_data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'},
    )
