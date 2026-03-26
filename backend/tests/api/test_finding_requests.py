"""API tests for finding request endpoints (D15)."""

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
from app.models.finding_request import FindingRequest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_ORG_ID = uuid.uuid4()
NOW = datetime.now(timezone.utc)


def _make_user(role: str = "developer", org_id: uuid.UUID | None = None) -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(uuid.uuid4()),
        org_id=str(org_id or FAKE_ORG_ID),
        role=role,
        scopes=["scan:read", "scan:write"],
    )


def _make_mock_finding(org_id: uuid.UUID | None = None) -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.org_id = org_id or FAKE_ORG_ID
    f.project_id = uuid.uuid4()
    f.scan_id = uuid.uuid4()
    f.status = "open"
    f.assigned_to = None
    f.updated_at = NOW
    return f


def _make_mock_request(
    org_id: uuid.UUID | None = None,
    requested_by: uuid.UUID | None = None,
) -> MagicMock:
    r = MagicMock(spec=FindingRequest)
    r.id = uuid.uuid4()
    r.finding_id = uuid.uuid4()
    r.org_id = org_id or FAKE_ORG_ID
    r.requested_by = requested_by or uuid.uuid4()
    r.reviewed_by = None
    r.request_type = "false_positive"
    r.status = "pending"
    r.justification = "Not a real finding"
    r.review_note = None
    r.expires_at = None
    r.reviewed_at = None
    r.created_at = NOW
    r.updated_at = NOW
    return r


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
# POST /api/v1/findings/{id}/request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_request_endpoint(app, client: AsyncClient) -> None:
    """Dev can create a FP request."""
    user = _make_user("developer")
    finding = _make_mock_finding()

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

    mock_request_obj = _make_mock_request(org_id=user.org_id, requested_by=user.user_id)
    with patch("app.api.v1.finding_requests.finding_request_service") as mock_svc, \
         patch("app.services.finding_request_service.audit_service") as mock_audit:
        mock_svc.create_request = AsyncMock(return_value=mock_request_obj)
        mock_audit.log = AsyncMock()
        response = await client.post(
            f"/api/v1/findings/{finding.id}/request",
            json={
                "requestType": "false_positive",
                "justification": "This is not a real finding",
            },
        )

    assert response.status_code == 201

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/requests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_requests_endpoint(app, client: AsyncClient) -> None:
    """List requests endpoint should return paginated results."""
    user = _make_user("security_manager")

    mock_session = AsyncMock()

    count_result = MagicMock()
    count_result.scalar_one.return_value = 0

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

    response = await client.get("/api/v1/requests")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["items"] == []

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/v1/requests/{id}/approve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_request_endpoint(app, client: AsyncClient) -> None:
    """SM can approve a pending request."""
    approver_id = uuid.uuid4()
    user = AuthenticatedUser(
        user_id=str(approver_id),
        org_id=str(FAKE_ORG_ID),
        role="security_manager",
        scopes=["scan:read", "scan:write"],
    )

    requester_id = uuid.uuid4()
    request = _make_mock_request(requested_by=requester_id)
    finding = _make_mock_finding()
    request.finding_id = finding.id

    mock_session = AsyncMock()

    # First execute: load request; second: load finding
    req_result = MagicMock()
    req_result.scalar_one_or_none.return_value = request
    finding_result = MagicMock()
    finding_result.scalar_one_or_none.return_value = finding
    mock_session.execute = AsyncMock(side_effect=[req_result, finding_result])
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    with patch("app.services.finding_request_service.audit_service") as mock_audit:
        mock_audit.log = AsyncMock()
        response = await client.post(f"/api/v1/requests/{request.id}/approve")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/v1/requests/{id}/reject
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_request_endpoint(app, client: AsyncClient) -> None:
    """SM can reject a pending request."""
    user = _make_user("security_manager")
    request = _make_mock_request()

    mock_session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = request
    mock_session.execute = AsyncMock(return_value=result_mock)
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    async def _override_session():
        yield mock_session

    async def _override_user():
        return user

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    with patch("app.services.finding_request_service.audit_service") as mock_audit:
        mock_audit.log = AsyncMock()
        response = await client.post(
            f"/api/v1/requests/{request.id}/reject",
            json={"reason": "Insufficient evidence"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "rejected"

    app.dependency_overrides.clear()
