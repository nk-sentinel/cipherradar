"""Tests for the reports API endpoint.

These tests mock the database layer and verify the endpoint returns
correct content-types and response structure.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


def _make_mock_scan(scan_id: uuid.UUID, status: str = "completed") -> MagicMock:
    """Create a mock Scan object."""
    scan = MagicMock()
    scan.id = scan_id
    scan.status = status
    scan.cbom_document = MagicMock()
    scan.cbom_document.cbom_json = {"components": []}
    scan.cbom_document.spec_version = "1.7"
    return scan


def _make_mock_finding(name: str = "RSA-2048", severity: str = "high") -> MagicMock:
    """Create a mock Finding object."""
    finding = MagicMock()
    finding.name = name
    finding.severity = severity
    finding.confidence = "high"
    finding.quantum_status = "vulnerable"
    finding.asset_type = "asymmetric-key"
    finding.location_file = "src/crypto.py"
    finding.location_line = 10
    finding.rule_id = "cbom-python-rsa"
    finding.properties = None
    return finding


@pytest.mark.asyncio
async def test_report_pdf_returns_correct_content_type(client: AsyncClient) -> None:
    """GET /api/v1/scans/{id}/reports?format=pdf should return application/pdf."""
    scan_id = uuid.uuid4()

    with (
        patch("app.api.v1.reports._assemble_scan_data", new_callable=AsyncMock) as mock_assemble,
        patch("app.services.report_service.generate_pdf_report", new_callable=AsyncMock) as mock_pdf,
    ):
        mock_assemble.return_value = {"scan_id": str(scan_id), "findings": []}
        mock_pdf.return_value = b"%PDF-1.4 fake content"

        response = await client.get(
            f"/api/v1/scans/{scan_id}/reports",
            params={"format": "pdf", "type": "findings-summary"},
        )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "Content-Disposition" in response.headers


@pytest.mark.asyncio
async def test_report_html_returns_correct_content_type(client: AsyncClient) -> None:
    """GET /api/v1/scans/{id}/reports?format=html should return text/html."""
    scan_id = uuid.uuid4()

    with (
        patch("app.api.v1.reports._assemble_scan_data", new_callable=AsyncMock) as mock_assemble,
        patch("app.services.report_service.generate_html_report", new_callable=AsyncMock) as mock_html,
    ):
        mock_assemble.return_value = {"scan_id": str(scan_id), "findings": []}
        mock_html.return_value = "<html><body>Report</body></html>"

        response = await client.get(
            f"/api/v1/scans/{scan_id}/reports",
            params={"format": "html", "type": "quantum-readiness"},
        )

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


@pytest.mark.asyncio
async def test_report_csv_returns_correct_content_type(client: AsyncClient) -> None:
    """GET /api/v1/scans/{id}/reports?format=csv should return text/csv."""
    scan_id = uuid.uuid4()

    with (
        patch("app.api.v1.reports._assemble_scan_data", new_callable=AsyncMock) as mock_assemble,
        patch("app.services.report_service.generate_csv_report", new_callable=AsyncMock) as mock_csv,
    ):
        mock_assemble.return_value = {"scan_id": str(scan_id), "findings": []}
        mock_csv.return_value = "scan_id,name\nval1,val2\n"

        response = await client.get(
            f"/api/v1/scans/{scan_id}/reports",
            params={"format": "csv"},
        )

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "Content-Disposition" in response.headers
