"""API tests for finding status endpoints (D14, D17)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.main import create_app
from app.models.finding import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_ORG_ID = uuid.uuid4()
FAKE_FINDING_ID = uuid.uuid4()
NOW = datetime.now(timezone.utc)


def _make_user(role: str = "security_engineer", org_id: uuid.UUID | None = None) -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(uuid.uuid4()),
        org_id=str(org_id or FAKE_ORG_ID),
        role=role,
        scopes=["scan:read", "scan:write"],
    )


def _make_mock_finding(
    status: str = "open",
    org_id: uuid.UUID | None = None,
) -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = FAKE_FINDING_ID
    f.org_id = org_id or FAKE_ORG_ID
    f.project_id = uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.status = status
    f.assigned_to = None
    f.reopen_count = 0
    f.last_reopened_at = None
    f.updated_at = NOW
    return f


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


# ---------------------------------------------------------------------------
# PATCH /api/v1/findings/{id}/status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_status_endpoint_success(app, client: AsyncClient) -> None:
    """Successful status change should return 200 with updated finding."""
    user = _make_user("security_engineer")
    finding = _make_mock_finding("open")

    mock_session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = finding
    mock_session.execute = AsyncMock(return_value=result_mock)
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    with patch("app.services.finding_status_service.audit_service") as mock_audit:
        mock_audit.log = AsyncMock()
        response = await client.patch(
            f"/api/v1/findings/{FAKE_FINDING_ID}/status",
            json={"status": "in_review"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "in_review"
    assert body["id"] == str(FAKE_FINDING_ID)

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_change_status_endpoint_invalid_transition(app, client: AsyncClient) -> None:
    """Invalid transition should return 400."""
    user = _make_user("security_manager")
    finding = _make_mock_finding("in_progress")

    mock_session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = finding
    mock_session.execute = AsyncMock(return_value=result_mock)

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    response = await client.patch(
        f"/api/v1/findings/{FAKE_FINDING_ID}/status",
        json={"status": "risk_accepted"},
    )

    assert response.status_code == 400

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_change_status_endpoint_forbidden(app, client: AsyncClient) -> None:
    """Developer trying to mark FP should return 403."""
    user = _make_user("developer")
    finding = _make_mock_finding("open")

    mock_session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = finding
    mock_session.execute = AsyncMock(return_value=result_mock)

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    response = await client.patch(
        f"/api/v1/findings/{FAKE_FINDING_ID}/status",
        json={"status": "false_positive", "reason": "Not real"},
    )

    assert response.status_code == 403

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_change_status_endpoint_not_found(app, client: AsyncClient) -> None:
    """Non-existent finding should return 404."""
    user = _make_user("security_engineer")

    mock_session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=result_mock)

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    response = await client.patch(
        f"/api/v1/findings/{uuid.uuid4()}/status",
        json={"status": "in_review"},
    )

    assert response.status_code == 404

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# PATCH /api/v1/findings/{id}/assign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assign_endpoint_success(app, client: AsyncClient) -> None:
    """Successful assignment should return 200."""
    user = _make_user("security_manager")
    finding = _make_mock_finding("open")
    assignee_id = uuid.uuid4()

    mock_session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = finding
    mock_session.execute = AsyncMock(return_value=result_mock)
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    with patch("app.services.finding_status_service.audit_service") as mock_audit:
        mock_audit.log = AsyncMock()
        response = await client.patch(
            f"/api/v1/findings/{FAKE_FINDING_ID}/assign",
            json={"assigneeId": str(assignee_id)},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "in_review"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/findings/{id}/history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_history_endpoint_success(app, client: AsyncClient) -> None:
    """History endpoint should return paginated history."""
    user = _make_user("compliance_auditor")

    mock_session = AsyncMock()

    # Mock count query
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0

    # Mock data query
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = []
    data_result = MagicMock()
    data_result.scalars.return_value = scalars_mock

    mock_session.execute = AsyncMock(side_effect=[count_result, data_result])

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    response = await client.get(f"/api/v1/findings/{FAKE_FINDING_ID}/history")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["items"] == []

    app.dependency_overrides.clear()
