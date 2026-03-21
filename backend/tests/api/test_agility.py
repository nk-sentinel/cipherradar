"""Tests for agility score API endpoint."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.agility import AgilityScore, FactorScore

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
# GET /api/v1/projects/{id}/agility-score
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agility_score_endpoint(app, client: AsyncClient) -> None:
    """Agility score endpoint should return a properly structured score."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_score = AgilityScore(
        total_score=72.5,
        label="Moderately Agile",
        factors=[
            FactorScore(name="call_site_concentration", weight=0.20, score=75.0, details="7 files"),
            FactorScore(name="abstraction_level", weight=0.25, score=50.0, details="2/4 wrapped"),
            FactorScore(name="algorithm_diversity", weight=0.15, score=100.0, details="2 algorithms"),
            FactorScore(name="key_management", weight=0.20, score=75.0, details="KMS: 3"),
            FactorScore(name="migration_readiness", weight=0.20, score=100.0, details="4/4 replaceable"),
        ],
        recommendations=["Introduce crypto abstraction wrappers"],
    )

    with (
        patch(
            "app.api.v1.agility._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.agility._agility.compute_score",
            new_callable=AsyncMock,
            return_value=fake_score,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/agility-score")

    assert response.status_code == 200
    body = response.json()
    assert body["totalScore"] == 72.5
    assert body["label"] == "Moderately Agile"
    assert len(body["factors"]) == 5
    assert len(body["recommendations"]) == 1

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_agility_score_camel_case(app, client: AsyncClient) -> None:
    """Response should use camelCase field names."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_score = AgilityScore(
        total_score=85.0,
        label="Highly Agile",
        factors=[
            FactorScore(name="call_site_concentration", weight=0.20, score=100.0, details="2 files"),
            FactorScore(name="abstraction_level", weight=0.25, score=100.0, details="all wrapped"),
            FactorScore(name="algorithm_diversity", weight=0.15, score=100.0, details="1 algorithm"),
            FactorScore(name="key_management", weight=0.20, score=50.0, details="config-based"),
            FactorScore(name="migration_readiness", weight=0.20, score=100.0, details="all replaceable"),
        ],
    )

    with (
        patch(
            "app.api.v1.agility._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.agility._agility.compute_score",
            new_callable=AsyncMock,
            return_value=fake_score,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/agility-score")

    body = response.json()
    # Verify camelCase keys
    assert "totalScore" in body
    assert "factors" in body
    assert body["factors"][0]["name"] == "call_site_concentration"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_agility_score_has_required_fields(app, client: AsyncClient) -> None:
    """Response must contain all required fields."""
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_score = AgilityScore(
        total_score=60.0,
        label="Moderately Agile",
        factors=[
            FactorScore(name="f1", weight=0.20, score=60.0),
            FactorScore(name="f2", weight=0.25, score=60.0),
            FactorScore(name="f3", weight=0.15, score=60.0),
            FactorScore(name="f4", weight=0.20, score=60.0),
            FactorScore(name="f5", weight=0.20, score=60.0),
        ],
    )

    with (
        patch(
            "app.api.v1.agility._get_project_findings",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.agility._agility.compute_score",
            new_callable=AsyncMock,
            return_value=fake_score,
        ),
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/agility-score")

    body = response.json()
    required_keys = {"totalScore", "label", "factors", "recommendations"}
    assert required_keys.issubset(set(body.keys()))

    app.dependency_overrides.clear()
