from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture(autouse=True)
def _reset_policy_state():
    """Reset in-memory policy rule state between tests."""
    from app.api.v1.policy import _rule_enabled_state

    original = dict(_rule_enabled_state)
    yield
    _rule_enabled_state.clear()
    _rule_enabled_state.update(original)


# ---------------------------------------------------------------------------
# GET /api/v1/policy/rules — list rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_policy_rules(app, client_with_auth: AsyncClient) -> None:
    """GET /api/v1/policy/rules should return all 6 hardcoded policy rules."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    # Each rule triggers a count query — mock all 6 to return 0
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    mock_session.execute = AsyncMock(return_value=count_result)

    response = await client_with_auth.get("/api/v1/policy/rules")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 6
    assert len(body["rules"]) == 6

    rule_ids = [r["id"] for r in body["rules"]]
    assert "no-broken-algorithms" in rule_ids
    assert "no-ecb-mode" in rule_ids
    assert "rsa-min-key-size" in rule_ids
    assert "no-deprecated-tls" in rule_ids
    assert "quantum-vulnerable" in rule_ids
    assert "no-hardcoded-keys" in rule_ids

    # Verify camelCase field names
    first_rule = body["rules"][0]
    assert "violationCount" in first_rule

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# PUT /api/v1/policy/rules/{rule_id} — toggle rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_toggle_policy_rule(app, client_with_auth: AsyncClient) -> None:
    """PUT /api/v1/policy/rules/{rule_id} should toggle enabled state."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    count_result = MagicMock()
    count_result.scalar_one.return_value = 5
    mock_session.execute = AsyncMock(return_value=count_result)

    # Disable the rule
    response = await client_with_auth.put(
        "/api/v1/policy/rules/no-broken-algorithms",
        json={"enabled": False},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "no-broken-algorithms"
    assert body["enabled"] is False
    assert body["violationCount"] == 5

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_toggle_nonexistent_rule_returns_404(app, client_with_auth: AsyncClient) -> None:
    """PUT /api/v1/policy/rules/{rule_id} should return 404 for unknown rule."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    response = await client_with_auth.put(
        "/api/v1/policy/rules/nonexistent-rule",
        json={"enabled": False},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Toggle persistence within a test session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_toggle_persists_in_list(app, client_with_auth: AsyncClient) -> None:
    """After toggling a rule off, listing should reflect the disabled state."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    mock_session.execute = AsyncMock(return_value=count_result)

    # Disable a rule
    await client_with_auth.put(
        "/api/v1/policy/rules/no-ecb-mode",
        json={"enabled": False},
    )

    # List rules and check
    response = await client_with_auth.get("/api/v1/policy/rules")
    assert response.status_code == 200
    body = response.json()

    ecb_rule = next(r for r in body["rules"] if r["id"] == "no-ecb-mode")
    assert ecb_rule["enabled"] is False

    app.dependency_overrides.clear()
