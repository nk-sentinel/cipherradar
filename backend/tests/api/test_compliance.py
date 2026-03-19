"""Tests for compliance API endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.compliance import (
    ComplianceItem,
    ComplianceReport,
    MigrationItem,
    QuantumRiskScore,
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
    """Create a session dependency override."""
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    return _override


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/compliance/nist-800-131a
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nist_compliance_report(app, client: AsyncClient) -> None:
    """NIST endpoint should return a ComplianceReport with correct structure."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = ComplianceReport(
        framework="nist-800-131a",
        score=75.0,
        total_findings=4,
        compliant_count=2,
        non_compliant_count=2,
        items=[
            ComplianceItem(algorithm="aes", classification="acceptable", count=2, action_required="none"),
            ComplianceItem(
                algorithm="des",
                classification="disallowed",
                count=1,
                action_required="immediate-remediation",
            ),
            ComplianceItem(
                algorithm="rsa",
                classification="deprecated",
                count=1,
                action_required="schedule-migration",
            ),
        ],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch.object(
            type(ComplianceReport),
            "__init__",
            wraps=ComplianceReport.__init__,
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_nist_800_131a",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/nist-800-131a")

    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "nist-800-131a"
    assert body["score"] == 75.0
    assert body["total_findings"] == 4
    assert body["compliant_count"] == 2
    assert body["non_compliant_count"] == 2
    assert len(body["items"]) == 3

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/compliance/fips-140-3
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fips_compliance_report(app, client: AsyncClient) -> None:
    """FIPS endpoint should return a ComplianceReport."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = ComplianceReport(
        framework="fips-140-3",
        score=100.0,
        total_findings=2,
        compliant_count=2,
        non_compliant_count=0,
        items=[
            ComplianceItem(algorithm="aes", classification="approved", count=1, action_required="none"),
            ComplianceItem(algorithm="sha256", classification="approved", count=1, action_required="none"),
        ],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_fips_140_3",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/fips-140-3")

    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "fips-140-3"
    assert body["score"] == 100.0
    assert len(body["items"]) == 2

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/quantum-risk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quantum_risk_endpoint(app, client: AsyncClient) -> None:
    """Quantum risk endpoint should return a QuantumRiskScore."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_score = QuantumRiskScore(
        score=35.0,
        vulnerable_count=3,
        safe_count=5,
        broken_count=1,
        migration_items=[
            MigrationItem(algorithm="rsa", count=2, severity="high", migrate_to="ml-dsa", priority=1),
            MigrationItem(algorithm="des", count=1, severity="critical", migrate_to="", priority=2),
        ],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.compute_quantum_risk_score",
            new_callable=AsyncMock,
            return_value=fake_score,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/quantum-risk")

    assert response.status_code == 200
    body = response.json()
    assert body["score"] == 35.0
    assert body["vulnerable_count"] == 3
    assert body["safe_count"] == 5
    assert body["broken_count"] == 1
    assert len(body["migration_items"]) == 2

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/migration-priority
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migration_priority_endpoint(app, client: AsyncClient) -> None:
    """Migration priority endpoint should return a list of MigrationItem."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_items = [
        MigrationItem(algorithm="rsa", count=5, severity="high", migrate_to="ml-dsa", priority=1),
        MigrationItem(algorithm="ecdsa", count=2, severity="medium", migrate_to="ml-dsa", priority=2),
    ]

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.get_migration_priority_queue",
            new_callable=AsyncMock,
            return_value=fake_items,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/migration-priority")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[0]["algorithm"] == "rsa"
    assert body[0]["priority"] == 1
    assert body[1]["algorithm"] == "ecdsa"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Response schema validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_report_has_required_fields(app, client: AsyncClient) -> None:
    """Compliance report response must contain all required fields."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_report = ComplianceReport(
        framework="nist-800-131a",
        score=90.0,
        total_findings=1,
        compliant_count=1,
        non_compliant_count=0,
        items=[ComplianceItem(algorithm="aes", classification="acceptable", count=1, action_required="none")],
    )

    with (
        patch(
            "app.api.v1.compliance._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.compliance._compliance.evaluate_nist_800_131a",
            new_callable=AsyncMock,
            return_value=fake_report,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/compliance/nist-800-131a")

    body = response.json()
    required_keys = {"framework", "score", "total_findings", "compliant_count", "non_compliant_count", "items"}
    assert required_keys.issubset(set(body.keys()))

    app.dependency_overrides.clear()
