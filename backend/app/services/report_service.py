"""Report generation service: PDF, HTML, and CSV reports for scan results."""

import asyncio
import csv
import io
import logging
from pathlib import Path
from typing import Any

import jinja2
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

logger = logging.getLogger(__name__)

# Jinja2 environment pointing at app/templates/
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=jinja2.select_autoescape(["html"]),
)


def _build_pdf_quantum_readiness(scan_data: dict[str, Any]) -> bytes:
    """Build a quantum-readiness PDF report (sync, runs in thread)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=20)
    heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontSize=14, spaceAfter=10)

    elements: list[Any] = []

    # Title
    elements.append(Paragraph("Quantum Readiness Report", title_style))
    elements.append(Spacer(1, 12))

    # Scan metadata
    scan_id = scan_data.get("scan_id", "N/A")
    elements.append(Paragraph(f"Scan ID: {scan_id}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Quantum risk score
    qrs = scan_data.get("quantum_risk", {})
    score = qrs.get("score", 0)
    elements.append(Paragraph("Quantum Risk Score", heading_style))
    elements.append(Paragraph(f"Score: {score}/100", styles["Normal"]))
    elements.append(Paragraph(f"Vulnerable: {qrs.get('vulnerable_count', 0)}", styles["Normal"]))
    elements.append(Paragraph(f"Safe: {qrs.get('safe_count', 0)}", styles["Normal"]))
    elements.append(Paragraph(f"Broken: {qrs.get('broken_count', 0)}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Migration priorities table
    migration_items = qrs.get("migration_items", [])
    if migration_items:
        elements.append(Paragraph("Migration Priorities", heading_style))
        table_data = [["Priority", "Algorithm", "Count", "Severity", "Migrate To"]]
        for item in migration_items:
            table_data.append(
                [
                    str(item.get("priority", "")),
                    item.get("algorithm", ""),
                    str(item.get("count", "")),
                    item.get("severity", ""),
                    item.get("migrate_to", ""),
                ]
            )
        table = Table(table_data, colWidths=[0.8 * inch, 1.5 * inch, 0.8 * inch, 1.2 * inch, 1.5 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                ]
            )
        )
        elements.append(table)

    doc.build(elements)
    return buf.getvalue()


def _build_pdf_compliance_gap(scan_data: dict[str, Any]) -> bytes:
    """Build a compliance-gap PDF report (sync, runs in thread)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=20)
    heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontSize=14, spaceAfter=10)

    elements: list[Any] = []
    elements.append(Paragraph("Compliance Gap Report", title_style))
    elements.append(Spacer(1, 12))

    scan_id = scan_data.get("scan_id", "N/A")
    elements.append(Paragraph(f"Scan ID: {scan_id}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Compliance frameworks
    frameworks = scan_data.get("compliance", [])
    for fw in frameworks:
        fw_name = fw.get("framework", "Unknown")
        fw_score = fw.get("score", 0)
        elements.append(Paragraph(f"{fw_name} - Score: {fw_score}/100", heading_style))
        elements.append(Paragraph(f"Compliant: {fw.get('compliant_count', 0)}", styles["Normal"]))
        elements.append(Paragraph(f"Non-compliant: {fw.get('non_compliant_count', 0)}", styles["Normal"]))
        elements.append(Spacer(1, 6))

        items = fw.get("items", [])
        if items:
            table_data = [["Algorithm", "Classification", "Count", "Action"]]
            for item in items:
                table_data.append(
                    [
                        item.get("algorithm", ""),
                        item.get("classification", ""),
                        str(item.get("count", "")),
                        item.get("action_required", ""),
                    ]
                )
            table = Table(table_data, colWidths=[1.5 * inch, 1.5 * inch, 0.8 * inch, 2.0 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                    ]
                )
            )
            elements.append(table)
            elements.append(Spacer(1, 12))

    doc.build(elements)
    return buf.getvalue()


def _build_pdf_findings_summary(scan_data: dict[str, Any]) -> bytes:
    """Build a findings-summary PDF report (sync, runs in thread)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=20)
    heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontSize=14, spaceAfter=10)

    elements: list[Any] = []
    elements.append(Paragraph("Findings Summary Report", title_style))
    elements.append(Spacer(1, 12))

    scan_id = scan_data.get("scan_id", "N/A")
    elements.append(Paragraph(f"Scan ID: {scan_id}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    findings = scan_data.get("findings", [])
    elements.append(Paragraph(f"Total Findings: {len(findings)}", heading_style))
    elements.append(Spacer(1, 6))

    if findings:
        table_data = [["Name", "Severity", "Quantum Status", "File", "Line"]]
        for f in findings:
            table_data.append(
                [
                    f.get("name", "")[:40],
                    f.get("severity", ""),
                    f.get("quantum_status", ""),
                    f.get("location_file", "")[-30:],
                    str(f.get("location_line", "")),
                ]
            )
        table = Table(table_data, colWidths=[1.8 * inch, 0.8 * inch, 1.2 * inch, 1.8 * inch, 0.5 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                ]
            )
        )
        elements.append(table)

    doc.build(elements)
    return buf.getvalue()


_PDF_BUILDERS = {
    "quantum-readiness": _build_pdf_quantum_readiness,
    "compliance-gap": _build_pdf_compliance_gap,
    "findings-summary": _build_pdf_findings_summary,
}


async def generate_pdf_report(scan_id: str, report_type: str, scan_data: dict[str, Any]) -> bytes:
    """Generate a PDF report for a scan.

    Args:
        scan_id: The scan identifier.
        report_type: One of "quantum-readiness", "compliance-gap", "findings-summary".
        scan_data: Pre-assembled scan data dict with keys like findings, compliance, quantum_risk.

    Returns:
        PDF content as bytes.
    """
    builder = _PDF_BUILDERS.get(report_type)
    if builder is None:
        msg = f"Unknown report type: {report_type}"
        raise ValueError(msg)

    scan_data["scan_id"] = scan_id
    # ReportLab is sync — run in thread pool
    return await asyncio.to_thread(builder, scan_data)


async def generate_html_report(scan_id: str, report_type: str, scan_data: dict[str, Any]) -> str:
    """Generate an HTML report for a scan using Jinja2 templates.

    Args:
        scan_id: The scan identifier.
        report_type: One of "quantum-readiness", "compliance-gap", "findings-summary".
        scan_data: Pre-assembled scan data dict.

    Returns:
        Rendered HTML string.
    """
    template_map = {
        "quantum-readiness": "quantum_readiness.html",
        "compliance-gap": "compliance_gap.html",
        "findings-summary": "findings_summary.html",
    }

    template_name = template_map.get(report_type)
    if template_name is None:
        msg = f"Unknown report type: {report_type}"
        raise ValueError(msg)

    scan_data["scan_id"] = scan_id
    template = _jinja_env.get_template(template_name)
    return template.render(**scan_data)


async def generate_csv_report(scan_id: str, scan_data: dict[str, Any]) -> str:
    """Generate a CSV report of findings for a scan.

    Args:
        scan_id: The scan identifier.
        scan_data: Pre-assembled scan data dict with a "findings" key.

    Returns:
        CSV content as string.
    """
    output = io.StringIO()
    fieldnames = [
        "scan_id",
        "name",
        "severity",
        "confidence",
        "quantum_status",
        "asset_type",
        "location_file",
        "location_line",
        "rule_id",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for finding in scan_data.get("findings", []):
        writer.writerow(
            {
                "scan_id": scan_id,
                "name": finding.get("name", ""),
                "severity": finding.get("severity", ""),
                "confidence": finding.get("confidence", ""),
                "quantum_status": finding.get("quantum_status", ""),
                "asset_type": finding.get("asset_type", ""),
                "location_file": finding.get("location_file", ""),
                "location_line": finding.get("location_line", ""),
                "rule_id": finding.get("rule_id", ""),
            }
        )

    return output.getvalue()
