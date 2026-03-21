from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.models.scan import ScanStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_SCAN_ID = uuid.uuid4()
FAKE_PROJECT_ID = uuid.uuid4()
NOW = datetime.now(UTC)


def _make_fake_scan(
    scan_id: uuid.UUID = FAKE_SCAN_ID,
    project_id: uuid.UUID = FAKE_PROJECT_ID,
    status: ScanStatus = ScanStatus.QUEUED,
) -> MagicMock:
    """Build a mock Scan ORM object that Pydantic's from_attributes can read."""
    scan = MagicMock(spec=["id", "project_id", "status", "branch", "commit_sha", "findings_count", "started_at", "completed_at", "created_at", "updated_at"])
    scan.id = scan_id
    scan.project_id = project_id
    scan.status = status.value
    scan.branch = "main"
    scan.commit_sha = "abc1234"
    scan.findings_count = 0
    scan.started_at = None
    scan.completed_at = None
    scan.created_at = NOW
    scan.updated_at = NOW
    return scan


def _make_fake_cbom_doc(scan_id: uuid.UUID = FAKE_SCAN_ID) -> MagicMock:
    """Build a mock CBOMDocument ORM object."""
    doc = MagicMock()
    doc.scan_id = scan_id
    doc.spec_version = "1.7"
    doc.serial_number = "urn:uuid:" + str(uuid.uuid4())
    doc.cbom_json = {
        "specVersion": "1.7",
        "components": [{"name": "AES-256-GCM", "type": "crypto-asset"}],
    }
    return doc


@pytest.fixture
def app():
    """Create a test app without lifespan (no DB required)."""
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    """Async HTTP client wired to the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# POST /api/v1/scans
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_scan_returns_201(app, client: AsyncClient) -> None:
    """POST /api/v1/scans should return 201 with correct fields."""
    fake_scan = _make_fake_scan()

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch("app.api.v1.scans.scan_service.create_scan", new_callable=AsyncMock) as mock_create:
        from app.schemas.scan import ScanResponse

        mock_create.return_value = ScanResponse.model_validate(fake_scan)

        response = await client.post(
            "/api/v1/scans",
            json={
                "project_id": str(FAKE_PROJECT_ID),
                "branch": "main",
                "commit_sha": "abc1234",
                "passes": [1, 2],
            },
        )

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(FAKE_SCAN_ID)
    assert body["projectId"] == str(FAKE_PROJECT_ID)
    assert body["status"] == "queued"
    assert body["branch"] == "main"
    assert body["findingsCount"] == 0

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_scan_returns_200(app, client: AsyncClient) -> None:
    """GET /api/v1/scans/{scan_id} should return 200 for an existing scan."""
    fake_scan = _make_fake_scan()

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch("app.api.v1.scans.scan_service.get_scan", new_callable=AsyncMock) as mock_get:
        from app.schemas.scan import ScanResponse

        mock_get.return_value = ScanResponse.model_validate(fake_scan)

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(FAKE_SCAN_ID)
    assert body["status"] == "queued"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_get_nonexistent_scan_returns_404(app, client: AsyncClient) -> None:
    """GET /api/v1/scans/{scan_id} should return 404 for a missing scan."""
    from fastapi import HTTPException

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch("app.api.v1.scans.scan_service.get_scan", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = HTTPException(status_code=404, detail="Scan not found")

        missing_id = uuid.uuid4()
        response = await client.get(f"/api/v1/scans/{missing_id}")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans (list with pagination)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_scans_with_pagination(app, client: AsyncClient) -> None:
    """GET /api/v1/scans should return paginated results."""
    fake_scans = [_make_fake_scan(scan_id=uuid.uuid4()) for _ in range(3)]

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch("app.api.v1.scans.scan_service.list_scans", new_callable=AsyncMock) as mock_list:
        from app.schemas.scan import ScanListResponse, ScanResponse

        mock_list.return_value = ScanListResponse(
            items=[ScanResponse.model_validate(s) for s in fake_scans],
            total=3,
            page=1,
            per_page=20,
        )

        response = await client.get("/api/v1/scans?page=1&per_page=20")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["perPage"] == 20
    assert len(body["items"]) == 3

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/cbom
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_scan_cbom(app, client: AsyncClient) -> None:
    """GET /api/v1/scans/{scan_id}/cbom should return the CBOM document."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch("app.api.v1.scans.scan_service.get_scan_cbom", new_callable=AsyncMock) as mock_cbom:
        from app.schemas.scan import CBOMResponse

        mock_cbom.return_value = CBOMResponse(
            scan_id=FAKE_SCAN_ID,
            spec_version="1.7",
            serial_number="urn:uuid:" + str(uuid.uuid4()),
            components_count=1,
            cbom_json={
                "specVersion": "1.7",
                "components": [{"name": "AES-256-GCM", "type": "crypto-asset"}],
            },
        )

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/cbom")

    assert response.status_code == 200
    body = response.json()
    assert body["scanId"] == str(FAKE_SCAN_ID)
    assert body["specVersion"] == "1.7"
    assert body["componentsCount"] == 1
    assert "components" in body["cbomJson"]

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_get_cbom_for_nonexistent_scan_returns_404(app, client: AsyncClient) -> None:
    """GET /api/v1/scans/{scan_id}/cbom should return 404 when scan has no CBOM."""
    from fastapi import HTTPException

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    with patch("app.api.v1.scans.scan_service.get_scan_cbom", new_callable=AsyncMock) as mock_cbom:
        mock_cbom.side_effect = HTTPException(status_code=404, detail="CBOM not found for this scan")

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/cbom")

    assert response.status_code == 404

    app.dependency_overrides.clear()
