"""Tests for portfolio API endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.main import create_app
from app.schemas.portfolio import (
    FrameworkScore,
    HeatMapEntry,
    MigrationPriorityItem,
    PortfolioCompliance,
    PortfolioQuantum,
    PortfolioSummary,
    QuantumCategory,
    TopRepo,
)

FAKE_USER_ID = str(uuid.uuid4())
FAKE_ORG_ID = str(uuid.uuid4())
FAKE_PROJECT_ID_1 = str(uuid.uuid4())
FAKE_PROJECT_ID_2 = str(uuid.uuid4())


def _make_user(
    *,
    assignment_level: str = "org",
    assigned_group_id: str | None = None,
) -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=FAKE_USER_ID,
        org_id=FAKE_ORG_ID,
        role="team_manager",
        scopes=["scan:read", "cbom:read", "report:read"],
        assignment_level=assignment_level,
        assigned_group_id=assigned_group_id,
    )


def _mock_session_override():
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    return _override


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# GET /api/v1/portfolio/summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_summary_returns_correct_structure(app, client: AsyncClient) -> None:
    """Summary endpoint should return a PortfolioSummary with all fields."""
    user = _make_user()
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user] = lambda: user

    fake_summary = PortfolioSummary(
        total_repos=2,
        total_findings=15,
        quantum_readiness_pct=60.0,
        heat_map=[
            HeatMapEntry(
                project_id=FAKE_PROJECT_ID_1,
                project_name="repo-alpha",
                critical=2,
                high=3,
                medium=4,
                low=1,
            ),
            HeatMapEntry(
                project_id=FAKE_PROJECT_ID_2,
                project_name="repo-beta",
                critical=0,
                high=1,
                medium=2,
                low=2,
            ),
        ],
        top_riskiest_repos=[
            TopRepo(
                project_id=FAKE_PROJECT_ID_1,
                project_name="repo-alpha",
                total_findings=10,
                critical_count=2,
                high_count=3,
                risk_score=57.0,
            ),
        ],
    )

    with (
        patch(
            "app.api.v1.portfolio.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[uuid.UUID(FAKE_PROJECT_ID_1), uuid.UUID(FAKE_PROJECT_ID_2)],
        ),
        patch(
            "app.api.v1.portfolio.get_portfolio_summary",
            new_callable=AsyncMock,
            return_value=fake_summary,
        ),
    ):
        response = await client.get("/api/v1/portfolio/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["totalRepos"] == 2
    assert body["totalFindings"] == 15
    assert body["quantumReadinessPct"] == 60.0
    assert len(body["heatMap"]) == 2
    assert len(body["topRiskiestRepos"]) == 1
    assert body["topRiskiestRepos"][0]["riskScore"] == 57.0

    # Verify heat map entry structure
    hm = body["heatMap"][0]
    assert "projectId" in hm
    assert "projectName" in hm
    assert "critical" in hm
    assert "high" in hm
    assert "medium" in hm
    assert "low" in hm

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/portfolio/compliance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_compliance_returns_all_frameworks(app, client: AsyncClient) -> None:
    """Compliance endpoint should return scores for all 6 frameworks."""
    user = _make_user()
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user] = lambda: user

    fake_compliance = PortfolioCompliance(
        frameworks=[
            FrameworkScore(framework="nist-800-131a", avg_score=85.0, total_compliant=10, total_non_compliant=2, repos_evaluated=2),
            FrameworkScore(framework="fips-140-3", avg_score=90.0, total_compliant=12, total_non_compliant=1, repos_evaluated=2),
            FrameworkScore(framework="pci-dss-v4", avg_score=78.0, total_compliant=8, total_non_compliant=3, repos_evaluated=2),
            FrameworkScore(framework="cnsa-2", avg_score=70.0, total_compliant=7, total_non_compliant=4, repos_evaluated=2),
            FrameworkScore(framework="iso-27001-a8-24", avg_score=82.0, total_compliant=9, total_non_compliant=2, repos_evaluated=2),
            FrameworkScore(framework="eu-cra", avg_score=88.0, total_compliant=11, total_non_compliant=1, repos_evaluated=2),
        ]
    )

    with (
        patch(
            "app.api.v1.portfolio.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[uuid.UUID(FAKE_PROJECT_ID_1)],
        ),
        patch(
            "app.api.v1.portfolio.get_portfolio_compliance",
            new_callable=AsyncMock,
            return_value=fake_compliance,
        ),
    ):
        response = await client.get("/api/v1/portfolio/compliance")

    assert response.status_code == 200
    body = response.json()
    assert len(body["frameworks"]) == 6
    frameworks = {f["framework"] for f in body["frameworks"]}
    assert "nist-800-131a" in frameworks
    assert "fips-140-3" in frameworks
    assert "pci-dss-v4" in frameworks
    assert "cnsa-2" in frameworks
    assert "iso-27001-a8-24" in frameworks
    assert "eu-cra" in frameworks

    # Verify framework score structure
    fw = body["frameworks"][0]
    assert "avgScore" in fw
    assert "totalCompliant" in fw
    assert "totalNonCompliant" in fw
    assert "reposEvaluated" in fw

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/portfolio/quantum
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_quantum_returns_correct_structure(app, client: AsyncClient) -> None:
    """Quantum endpoint should return counts and migration priority."""
    user = _make_user()
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user] = lambda: user

    fake_quantum = PortfolioQuantum(
        counts=QuantumCategory(vulnerable=5, safe=10, broken=2, unknown=1),
        migration_priority=[
            MigrationPriorityItem(algorithm="rsa", total_count=3, affected_repos=2, migrate_to="ml-dsa", priority=1),
            MigrationPriorityItem(algorithm="des", total_count=2, affected_repos=1, migrate_to="", priority=2),
        ],
    )

    with (
        patch(
            "app.api.v1.portfolio.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[uuid.UUID(FAKE_PROJECT_ID_1)],
        ),
        patch(
            "app.api.v1.portfolio.get_portfolio_quantum",
            new_callable=AsyncMock,
            return_value=fake_quantum,
        ),
    ):
        response = await client.get("/api/v1/portfolio/quantum")

    assert response.status_code == 200
    body = response.json()
    assert body["counts"]["vulnerable"] == 5
    assert body["counts"]["safe"] == 10
    assert body["counts"]["broken"] == 2
    assert body["counts"]["unknown"] == 1
    assert len(body["migrationPriority"]) == 2
    assert body["migrationPriority"][0]["algorithm"] == "rsa"
    assert body["migrationPriority"][0]["migrateTo"] == "ml-dsa"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Group scoping — Team Manager sees only their group
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_summary_group_scoped(app, client: AsyncClient) -> None:
    """Team Manager with group assignment should only see repos in their group."""
    group_id = str(uuid.uuid4())
    user = _make_user(assignment_level="group", assigned_group_id=group_id)
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user] = lambda: user

    group_project_id = uuid.UUID(FAKE_PROJECT_ID_1)

    fake_summary = PortfolioSummary(
        total_repos=1,
        total_findings=5,
        quantum_readiness_pct=80.0,
        heat_map=[
            HeatMapEntry(
                project_id=FAKE_PROJECT_ID_1,
                project_name="group-repo",
                critical=1,
                high=2,
                medium=1,
                low=1,
            ),
        ],
        top_riskiest_repos=[],
    )

    with (
        patch(
            "app.api.v1.portfolio.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[group_project_id],
        ) as mock_access,
        patch(
            "app.api.v1.portfolio.get_portfolio_summary",
            new_callable=AsyncMock,
            return_value=fake_summary,
        ),
    ):
        response = await client.get("/api/v1/portfolio/summary")

    assert response.status_code == 200
    body = response.json()
    # Verify only the group-scoped project is returned
    assert body["totalRepos"] == 1
    assert body["heatMap"][0]["projectName"] == "group-repo"

    # Verify get_accessible_project_ids was called with the user
    mock_access.assert_called_once()

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Empty portfolio (no accessible repos)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portfolio_summary_empty(app, client: AsyncClient) -> None:
    """Summary should handle zero accessible repos gracefully."""
    user = _make_user()
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user] = lambda: user

    fake_summary = PortfolioSummary(
        total_repos=0,
        total_findings=0,
        quantum_readiness_pct=100.0,
        heat_map=[],
        top_riskiest_repos=[],
    )

    with (
        patch(
            "app.api.v1.portfolio.get_accessible_project_ids",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.v1.portfolio.get_portfolio_summary",
            new_callable=AsyncMock,
            return_value=fake_summary,
        ),
    ):
        response = await client.get("/api/v1/portfolio/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["totalRepos"] == 0
    assert body["totalFindings"] == 0
    assert body["quantumReadinessPct"] == 100.0
    assert body["heatMap"] == []
    assert body["topRiskiestRepos"] == []

    app.dependency_overrides.clear()
