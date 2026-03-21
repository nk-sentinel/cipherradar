"""Tests for runtime enrichment API endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.runtime import EnrichedFinding, RuntimeSummary

FAKE_PROJECT_ID = uuid.uuid4()
FAKE_SCAN_ID = uuid.uuid4()


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
# POST /api/v1/runtime/enrich
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_runtime_observations(app, client: AsyncClient) -> None:
    """Ingest endpoint should accept a batch of observations."""
    app.dependency_overrides[get_session] = _mock_session_override()

    with (
        patch(
            "app.api.v1.runtime._verify_project",
            new_callable=AsyncMock,
            return_value=AsyncMock(org_id=uuid.uuid4()),
        ),
        patch(
            "app.api.v1.runtime._runtime.ingest_batch",
            new_callable=AsyncMock,
            return_value=2,
        ),
    ):
        response = await client.post(
            "/api/v1/runtime/enrich",
            json={
                "observations": [
                    {
                        "serviceName": "payment-svc",
                        "tlsVersion": "1.3",
                        "cipherSuite": "TLS_AES_256_GCM_SHA384",
                        "timestamp": "2026-03-22T10:00:00Z",
                        "projectId": str(FAKE_PROJECT_ID),
                    },
                    {
                        "serviceName": "auth-svc",
                        "tlsVersion": "1.2",
                        "cipherSuite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                        "timestamp": "2026-03-22T10:01:00Z",
                        "projectId": str(FAKE_PROJECT_ID),
                    },
                ],
            },
        )

    assert response.status_code == 201
    body = response.json()
    assert body["ingested"] == 2

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_ingest_empty_batch(app, client: AsyncClient) -> None:
    """Empty batch should return ingested: 0."""
    app.dependency_overrides[get_session] = _mock_session_override()

    response = await client.post(
        "/api/v1/runtime/enrich",
        json={"observations": []},
    )

    assert response.status_code == 201
    assert response.json()["ingested"] == 0

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{id}/runtime/summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runtime_summary(app, client: AsyncClient) -> None:
    """Summary endpoint should return aggregated observation data."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_summary = RuntimeSummary(
        project_id=FAKE_PROJECT_ID,
        total_observations=10,
        unique_tls_versions=["1.2", "1.3"],
        unique_cipher_suites=["TLS_AES_256_GCM_SHA384"],
        services_observed=["payment-svc", "auth-svc"],
        mismatches=1,
    )

    with (
        patch(
            "app.api.v1.runtime._verify_project",
            new_callable=AsyncMock,
        ),
        patch(
            "app.api.v1.runtime._runtime.get_runtime_summary",
            new_callable=AsyncMock,
            return_value=fake_summary,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/runtime/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["totalObservations"] == 10
    assert len(body["uniqueTlsVersions"]) == 2
    assert "payment-svc" in body["servicesObserved"]

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{id}/runtime/enriched
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enriched_findings(app, client: AsyncClient) -> None:
    """Enriched findings endpoint should return findings with runtime data."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_enriched = [
        EnrichedFinding(
            finding_id=uuid.uuid4(),
            rule_id="cbom-java-aes",
            name="AES-256 encryption",
            severity="medium",
            location_file="src/Crypto.java",
            location_line=42,
            runtime_observed=True,
            observed_tls_version="1.3",
            observed_cipher="TLS_AES_256_GCM_SHA384",
            mismatch=False,
        ),
    ]

    with patch(
        "app.api.v1.runtime._runtime.get_enriched_findings",
        new_callable=AsyncMock,
        return_value=fake_enriched,
    ):
        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/runtime/enriched")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["runtimeObserved"] is True
    assert body[0]["observedTlsVersion"] == "1.3"
    assert body[0]["mismatch"] is False

    app.dependency_overrides.clear()
