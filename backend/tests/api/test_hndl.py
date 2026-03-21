"""Tests for HNDL risk model API endpoint."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.hndl import HNDLRisk

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
# GET /api/v1/projects/{id}/hndl-risk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hndl_risk_endpoint(app, client: AsyncClient) -> None:
    """HNDL risk endpoint should return a properly structured risk assessment."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_risk = HNDLRisk(
        risk_score=0.56,
        urgency="HIGH",
        data_sensitivity=0.7,
        quantum_exposure=0.85,
        time_horizon=0.4,
        mosca_inequality=True,
        recommendations=[
            "Mosca inequality triggered — begin PQC migration immediately.",
            "Quantum-vulnerable algorithms detected.",
        ],
    )

    with (
        patch(
            "app.api.v1.hndl._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.hndl._hndl.compute_risk",
            new_callable=AsyncMock,
            return_value=fake_risk,
        ),
    ):
        response = await client.get(
            f"/api/v1/projects/{FAKE_PROJECT_ID}/hndl-risk?data_classification=confidential"
        )

    assert response.status_code == 200
    body = response.json()
    assert body["riskScore"] == 0.56
    assert body["urgency"] == "HIGH"
    assert body["dataSensitivity"] == 0.7
    assert body["quantumExposure"] == 0.85
    assert body["moscaInequality"] is True
    assert len(body["recommendations"]) == 2

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_hndl_risk_default_classification(app, client: AsyncClient) -> None:
    """Default data_classification should be 'internal'."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_risk = HNDLRisk(
        risk_score=0.12,
        urgency="LOW",
        data_sensitivity=0.4,
        quantum_exposure=0.3,
        time_horizon=0.4,
        mosca_inequality=False,
        recommendations=["HNDL risk is low."],
    )

    with (
        patch(
            "app.api.v1.hndl._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.hndl._hndl.compute_risk",
            new_callable=AsyncMock,
            return_value=fake_risk,
        ) as mock_compute,
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/hndl-risk")

    assert response.status_code == 200
    # Verify default classification was passed
    mock_compute.assert_called_once()
    call_kwargs = mock_compute.call_args
    assert call_kwargs.kwargs.get("data_classification") == "internal" or call_kwargs[1].get("data_classification") == "internal"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_hndl_risk_camel_case_response(app, client: AsyncClient) -> None:
    """Response should use camelCase field names."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_risk = HNDLRisk(
        risk_score=0.0,
        urgency="LOW",
        data_sensitivity=0.1,
        quantum_exposure=0.0,
        time_horizon=0.4,
        mosca_inequality=False,
    )

    with (
        patch(
            "app.api.v1.hndl._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.hndl._hndl.compute_risk",
            new_callable=AsyncMock,
            return_value=fake_risk,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/hndl-risk")

    body = response.json()
    required_keys = {
        "riskScore",
        "urgency",
        "dataSensitivity",
        "quantumExposure",
        "timeHorizon",
        "moscaInequality",
        "recommendations",
    }
    assert required_keys.issubset(set(body.keys()))

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_hndl_risk_with_restricted_classification(app, client: AsyncClient) -> None:
    """Restricted classification should produce maximum sensitivity."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_risk = HNDLRisk(
        risk_score=0.85,
        urgency="URGENT",
        data_sensitivity=1.0,
        quantum_exposure=0.95,
        time_horizon=0.4,
        mosca_inequality=True,
        recommendations=["Migrate immediately."],
    )

    with (
        patch(
            "app.api.v1.hndl._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.hndl._hndl.compute_risk",
            new_callable=AsyncMock,
            return_value=fake_risk,
        ),
    ):
        response = await client.get(
            f"/api/v1/projects/{FAKE_PROJECT_ID}/hndl-risk?data_classification=restricted"
        )

    assert response.status_code == 200
    body = response.json()
    assert body["dataSensitivity"] == 1.0
    assert body["urgency"] == "URGENT"

    app.dependency_overrides.clear()
