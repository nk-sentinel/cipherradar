"""Tests for scan upload API endpoint (ADR-025)."""

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import AuthenticatedUser, get_current_user_or_api_key
from app.db.session import get_session
from app.main import create_app


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


def _mock_user(org_id: str = "", scopes: list[str] | None = None) -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(uuid.uuid4()),
        org_id=org_id or str(uuid.uuid4()),
        role="developer",
        scopes=scopes or ["project:write", "scan:write"],
        auth_method="api_key",
    )


def _mock_user_override(user: AuthenticatedUser):
    async def _override():
        return user

    return _override


@pytest.mark.asyncio
async def test_upload_scan_success(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user_or_api_key] = _mock_user_override(_mock_user())

    scan_id = uuid.uuid4()
    project_id = uuid.uuid4()
    now = datetime.now(tz=UTC)

    fake_result = {
        "scan_id": scan_id,
        "project_id": project_id,
        "project_name": "my-project",
        "group_path": "default",
        "findings_count": 2,
        "status": "completed",
        "created_at": now,
    }
    fake_warnings = ["No group_path provided, using default group"]

    with patch(
        "app.api.v1.scan_upload.process_scan_upload",
        new_callable=AsyncMock,
        return_value=(fake_result, fake_warnings),
    ):
        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [
                {"name": "AES-256"},
                {"name": "RSA-2048"},
            ],
        }
        response = await client.post(
            "/api/v1/scans/upload?project_name=my-project",
            content=json.dumps(cbom),
            headers={"Authorization": "Bearer cbom_sk_test_key"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["project_name"] == "my-project"
    assert body["findings_count"] == 2
    assert body["status"] == "completed"
    assert len(body["warnings"]) == 1
    # Check X-CipherRadar-Warning header
    assert "x-cipherradar-warning" in response.headers

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_upload_scan_with_group_and_branch(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user_or_api_key] = _mock_user_override(_mock_user())

    scan_id = uuid.uuid4()
    project_id = uuid.uuid4()
    now = datetime.now(tz=UTC)

    fake_result = {
        "scan_id": scan_id,
        "project_id": project_id,
        "project_name": "my-project",
        "group_path": "team-alpha",
        "findings_count": 1,
        "status": "completed",
        "created_at": now,
    }

    with patch(
        "app.api.v1.scan_upload.process_scan_upload",
        new_callable=AsyncMock,
        return_value=(fake_result, []),
    ):
        cbom = {"bomFormat": "CycloneDX", "components": [{"name": "AES-256"}]}
        response = await client.post(
            "/api/v1/scans/upload?project_name=my-project&group_path=team-alpha&branch=main&commit_sha=abc123",
            content=json.dumps(cbom),
            headers={"Authorization": "Bearer cbom_sk_test_key"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["group_path"] == "team-alpha"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_upload_requires_project_name(app, client: AsyncClient) -> None:
    """project_name query parameter is required."""
    app.dependency_overrides[get_session] = _mock_session_override()
    app.dependency_overrides[get_current_user_or_api_key] = _mock_user_override(_mock_user())

    response = await client.post(
        "/api/v1/scans/upload",
        content=b'{"bomFormat": "CycloneDX", "components": []}',
        headers={"Authorization": "Bearer cbom_sk_test_key"},
    )

    # Missing required query param should return 422
    assert response.status_code == 422

    app.dependency_overrides.clear()
