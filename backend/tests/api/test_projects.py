import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.models.scan import ScanStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_PROJECT_ID = uuid.uuid4()
FAKE_ORG_ID = uuid.uuid4()
NOW = datetime.now(UTC)


def _make_fake_project() -> MagicMock:
    """Build a mock Project ORM object."""
    project = MagicMock()
    project.id = FAKE_PROJECT_ID
    project.org_id = FAKE_ORG_ID
    project.name = "test-project"
    return project


def _make_fake_scan(
    scan_id: uuid.UUID | None = None,
    status: ScanStatus = ScanStatus.COMPLETED,
) -> MagicMock:
    """Build a mock Scan ORM object."""
    scan = MagicMock(
        spec=[
            "id", "project_id", "org_id", "status", "branch",
            "commit_sha", "findings_count", "started_at",
            "completed_at", "created_at", "updated_at",
        ]
    )
    scan.id = scan_id or uuid.uuid4()
    scan.project_id = FAKE_PROJECT_ID
    scan.org_id = FAKE_ORG_ID
    scan.status = status.value
    scan.branch = "main"
    scan.commit_sha = "abc1234"
    scan.findings_count = 5
    scan.started_at = NOW
    scan.completed_at = NOW
    scan.created_at = NOW
    scan.updated_at = NOW
    return scan


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{project_id}/scans — list scans for project
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_project_scans(app, client: AsyncClient) -> None:
    """GET /api/v1/projects/{project_id}/scans should return paginated scans."""
    fake_scans = [_make_fake_scan(scan_id=uuid.uuid4()) for _ in range(2)]

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    # Mock: project existence check
    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = _make_fake_project()

    # Mock: count query
    count_result = MagicMock()
    count_result.scalar_one.return_value = 2

    # Mock: scans fetch
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = fake_scans
    scans_result = MagicMock()
    scans_result.scalars.return_value = scalars_mock

    mock_session.execute = AsyncMock(
        side_effect=[project_result, count_result, scans_result]
    )

    response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/scans")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["page"] == 1
    assert body["perPage"] == 20
    assert len(body["items"]) == 2

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/repos/{project_id}/scans — alias route
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_repo_scans_alias(app, client: AsyncClient) -> None:
    """GET /api/v1/repos/{project_id}/scans should work as alias for projects."""
    fake_scans = [_make_fake_scan(scan_id=uuid.uuid4())]

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = _make_fake_project()

    count_result = MagicMock()
    count_result.scalar_one.return_value = 1

    scalars_mock = MagicMock()
    scalars_mock.all.return_value = fake_scans
    scans_result = MagicMock()
    scans_result.scalars.return_value = scalars_mock

    mock_session.execute = AsyncMock(
        side_effect=[project_result, count_result, scans_result]
    )

    response = await client.get(f"/api/v1/repos/{FAKE_PROJECT_ID}/scans")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/v1/projects/{project_id}/scans/trigger — trigger scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trigger_project_scan(app, client: AsyncClient) -> None:
    """POST /api/v1/projects/{project_id}/scans/trigger should create a queued scan."""
    fake_project = _make_fake_project()
    new_scan_id = uuid.uuid4()
    fake_scan = _make_fake_scan(scan_id=new_scan_id, status=ScanStatus.QUEUED)
    fake_scan.findings_count = 0
    fake_scan.started_at = None
    fake_scan.completed_at = None

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    # Mock: project existence check
    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = fake_project

    mock_session.execute = AsyncMock(return_value=project_result)
    mock_session.add = MagicMock()
    mock_session.flush = AsyncMock()

    # After refresh, the scan should have the expected attributes
    async def _fake_refresh(obj):
        obj.id = new_scan_id
        obj.project_id = FAKE_PROJECT_ID
        obj.org_id = FAKE_ORG_ID
        obj.status = ScanStatus.QUEUED.value
        obj.branch = None
        obj.commit_sha = None
        obj.findings_count = 0
        obj.started_at = None
        obj.completed_at = None
        obj.created_at = NOW
        obj.updated_at = NOW

    mock_session.refresh = AsyncMock(side_effect=_fake_refresh)
    mock_session.commit = AsyncMock()

    response = await client.post(f"/api/v1/projects/{FAKE_PROJECT_ID}/scans/trigger")

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued"
    assert body["findingsCount"] == 0

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{project_id}/scans — 404 for missing project
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_project_scans_not_found(app, client: AsyncClient) -> None:
    """Should return 404 when the project does not exist."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    project_result = MagicMock()
    project_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=project_result)

    missing_id = uuid.uuid4()
    response = await client.get(f"/api/v1/projects/{missing_id}/scans")

    assert response.status_code == 404
    assert response.json()["detail"] == "Project not found"

    app.dependency_overrides.clear()
