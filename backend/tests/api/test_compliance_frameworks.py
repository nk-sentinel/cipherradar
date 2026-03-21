"""Tests for new compliance framework API endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.compliance import (
    ComplianceItem,
    ComplianceReport,
    EvidenceItem,
    EvidenceReport,
    GapItem,
    GapReport,
)

FAKE_PROJECT_ID = uuid.uuid4()


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


def _mock_session_override():
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    return _override


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/compliance/pci-dss
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pci_dss_endpoint(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = ComplianceReport(
        framework="pci-dss-v4",
        score=80.0,
        total_findings=5,
        compliant_count=4,
        non_compliant_count=1,
        items=[
            ComplianceItem(algorithm="aes", classification="compliant", count=3, action_required="none"),
            ComplianceItem(
                algorithm="des",
                classification="non-compliant",
                count=1,
                note="[Req 2.2.7] DES is not strong cryptography per PCI-DSS",
                action_required="immediate-remediation",
            ),
        ],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_pci_dss_v4",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/pci-dss")

    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "pci-dss-v4"
    assert body["score"] == 80.0
    assert len(body["items"]) == 2

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/compliance/cnsa-2
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cnsa_2_endpoint(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = ComplianceReport(
        framework="cnsa-2",
        score=66.7,
        total_findings=3,
        compliant_count=2,
        non_compliant_count=1,
        items=[
            ComplianceItem(algorithm="aes", classification="approved", count=1, action_required="none"),
            ComplianceItem(algorithm="sha384", classification="approved", count=1, action_required="none"),
            ComplianceItem(
                algorithm="rsa",
                classification="deprecated",
                count=1,
                action_required="schedule-migration",
            ),
        ],
        migration_deadlines={"rsa": "2025"},
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_cnsa_2",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/cnsa-2")

    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "cnsa-2"
    assert body["migrationDeadlines"]["rsa"] == "2025"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/compliance/iso-27001
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_iso_27001_endpoint(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = EvidenceReport(
        framework="iso-27001-a8-24",
        total_checks=10,
        passed=4,
        failed=2,
        manual_review=4,
        items=[
            EvidenceItem(
                check_id="A.8.24-1",
                title="Cryptographic policy defined",
                description="A policy on the use of cryptographic controls.",
                status="manual-review",
                evidence=["Requires manual verification"],
            ),
            EvidenceItem(
                check_id="A.8.24-3",
                title="No broken algorithms in use",
                description="No classically broken algorithms detected.",
                status="fail",
                evidence=["Broken algorithms detected: des"],
                findings_count=1,
            ),
        ],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_iso_27001_a8_24",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/iso-27001")

    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "iso-27001-a8-24"
    assert body["totalChecks"] == 10
    assert body["passed"] == 4
    assert body["failed"] == 2
    assert len(body["items"]) == 2
    # Verify no 'score' key
    assert "score" not in body

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/compliance/eu-cra
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_eu_cra_endpoint(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = GapReport(
        framework="eu-cra",
        total_requirements=10,
        gaps_found=2,
        no_gaps=4,
        manual_review=4,
        items=[
            GapItem(
                requirement_id="CRA-ANNEX-I-1",
                title="Security by design",
                description="Products shall be designed to ensure appropriate cybersecurity.",
                gap_status="gap",
                affected_algorithms=["des"],
                affected_count=1,
                recommendation="Replace des with state-of-the-art algorithms",
            ),
            GapItem(
                requirement_id="CRA-ANNEX-I-4",
                title="Secure by default",
                description="Products shall be delivered with secure default configurations.",
                gap_status="manual-review",
                recommendation="Manual review required",
            ),
        ],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_eu_cra",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/eu-cra")

    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "eu-cra"
    assert body["gapsFound"] == 2
    assert body["totalRequirements"] == 10
    assert len(body["items"]) == 2
    # Verify no 'score' key
    assert "score" not in body

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Response schema validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_report_structure(app, client: AsyncClient) -> None:
    """EvidenceReport must contain checklist fields, not score."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = EvidenceReport(
        framework="iso-27001-a8-24",
        total_checks=5,
        passed=2,
        failed=1,
        manual_review=2,
        items=[],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_iso_27001_a8_24",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/iso-27001")

    body = response.json()
    required_keys = {"framework", "totalChecks", "passed", "failed", "manualReview", "items"}
    assert required_keys.issubset(set(body.keys()))

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_gap_report_structure(app, client: AsyncClient) -> None:
    """GapReport must contain gap analysis fields, not score."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = GapReport(
        framework="eu-cra",
        total_requirements=3,
        gaps_found=1,
        no_gaps=1,
        manual_review=1,
        items=[],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_eu_cra",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/eu-cra")

    body = response.json()
    required_keys = {"framework", "totalRequirements", "gapsFound", "noGaps", "manualReview", "items"}
    assert required_keys.issubset(set(body.keys()))

    app.dependency_overrides.clear()
