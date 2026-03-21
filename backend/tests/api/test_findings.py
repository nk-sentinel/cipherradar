import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_SCAN_ID = uuid.uuid4()
FAKE_PROJECT_ID = uuid.uuid4()
FAKE_ORG_ID = uuid.uuid4()
NOW = datetime.now(UTC)


def _make_fake_finding(
    finding_id: uuid.UUID | None = None,
    severity: str = "high",
    quantum_status: str = "broken",
    name: str = "MD5 hash function",
    rule_id: str = "cbom-python-md5-usage",
    location_file: str = "hash.py",
    location_line: int = 12,
) -> MagicMock:
    """Build a mock Finding ORM object."""
    f = MagicMock(
        spec=[
            "id", "scan_id", "project_id", "org_id",
            "rule_id", "name", "severity", "confidence",
            "quantum_status", "asset_type", "location_file",
            "location_line", "properties", "created_at", "updated_at",
        ]
    )
    f.id = finding_id or uuid.uuid4()
    f.scan_id = FAKE_SCAN_ID
    f.project_id = FAKE_PROJECT_ID
    f.org_id = FAKE_ORG_ID
    f.rule_id = rule_id
    f.name = name
    f.severity = severity
    f.confidence = "high"
    f.quantum_status = quantum_status
    f.asset_type = "Hash"
    f.location_file = location_file
    f.location_line = location_line
    f.properties = {
        "algorithm": "MD5",
        "detection_pass": 1,
        "remediation": "Replace MD5 with SHA-256.",
    }
    f.created_at = NOW
    f.updated_at = NOW
    return f


def _make_fake_scan() -> MagicMock:
    """Build a minimal mock Scan ORM object for existence checks."""
    scan = MagicMock()
    scan.id = FAKE_SCAN_ID
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
# GET /api/v1/scans/{scan_id}/findings — paginated list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_findings_returns_paginated(app, client: AsyncClient) -> None:
    """GET /api/v1/scans/{scan_id}/findings should return paginated findings."""
    fake_findings = [_make_fake_finding(finding_id=uuid.uuid4()) for _ in range(3)]

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    # Mock scan existence check
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = _make_fake_scan()

    # Mock count query
    count_result = MagicMock()
    count_result.scalar_one.return_value = 3

    # Mock findings query
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = fake_findings
    findings_result = MagicMock()
    findings_result.scalars.return_value = scalars_mock

    mock_session.execute = AsyncMock(
        side_effect=[scan_result, count_result, findings_result]
    )

    response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/findings?page=1&per_page=20")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["perPage"] == 20
    assert len(body["items"]) == 3
    # Verify camelCase field names
    item = body["items"][0]
    assert "scanId" in item
    assert "quantumStatus" in item
    assert "ruleId" in item
    assert "assetType" in item

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/findings?severity=critical — severity filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_findings_severity_filter(app, client: AsyncClient) -> None:
    """Severity query param should filter findings."""
    fake_findings = [_make_fake_finding(severity="critical")]

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = _make_fake_scan()

    count_result = MagicMock()
    count_result.scalar_one.return_value = 1

    scalars_mock = MagicMock()
    scalars_mock.all.return_value = fake_findings
    findings_result = MagicMock()
    findings_result.scalars.return_value = scalars_mock

    mock_session.execute = AsyncMock(
        side_effect=[scan_result, count_result, findings_result]
    )

    response = await client.get(
        f"/api/v1/scans/{FAKE_SCAN_ID}/findings?severity=critical"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/findings?search=md5 — search filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_findings_search_filter(app, client: AsyncClient) -> None:
    """Search query param should filter findings by name, file, or rule_id."""
    fake_findings = [_make_fake_finding(name="MD5 hash function")]

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = _make_fake_scan()

    count_result = MagicMock()
    count_result.scalar_one.return_value = 1

    scalars_mock = MagicMock()
    scalars_mock.all.return_value = fake_findings
    findings_result = MagicMock()
    findings_result.scalars.return_value = scalars_mock

    mock_session.execute = AsyncMock(
        side_effect=[scan_result, count_result, findings_result]
    )

    response = await client.get(
        f"/api/v1/scans/{FAKE_SCAN_ID}/findings?search=md5"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/findings — 404 for missing scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_findings_scan_not_found(app, client: AsyncClient) -> None:
    """Should return 404 when the scan does not exist."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=scan_result)

    missing_id = uuid.uuid4()
    response = await client.get(f"/api/v1/scans/{missing_id}/findings")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"

    app.dependency_overrides.clear()
