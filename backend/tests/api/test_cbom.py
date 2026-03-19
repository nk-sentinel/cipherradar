"""Tests for CBOM management API endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.cbom import (
    CBOMDiff,
    CBOMDiffItem,
    CBOMVersion,
    ChangeType,
    MergedCBOM,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_PROJECT_ID = uuid.uuid4()
FAKE_SCAN_ID_1 = uuid.uuid4()
FAKE_SCAN_ID_2 = uuid.uuid4()
NOW = datetime.now(UTC)


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
# GET /api/v1/projects/{id}/cbom/versions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_cbom_versions(app, client: AsyncClient) -> None:
    """GET /api/v1/projects/{id}/cbom/versions should return a list of versions."""
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    app.dependency_overrides[get_session] = _override

    versions = [
        CBOMVersion(
            scan_id=FAKE_SCAN_ID_1,
            version_number=1,
            created_at=NOW,
            findings_count=3,
            spec_version="1.7",
        ),
        CBOMVersion(
            scan_id=FAKE_SCAN_ID_2,
            version_number=2,
            created_at=NOW,
            findings_count=5,
            spec_version="1.7",
        ),
    ]

    with patch("app.api.v1.cbom.cbom_service.get_versions", new_callable=AsyncMock) as mock_versions:
        mock_versions.return_value = versions
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/cbom/versions")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[0]["version_number"] == 1
    assert body[1]["version_number"] == 2
    assert body[0]["scan_id"] == str(FAKE_SCAN_ID_1)

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/cbom/diff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diff_endpoint(app, client: AsyncClient) -> None:
    """GET /api/v1/cbom/diff should return a diff structure."""
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    app.dependency_overrides[get_session] = _override

    diff = CBOMDiff(
        base_scan_id=FAKE_SCAN_ID_1,
        head_scan_id=FAKE_SCAN_ID_2,
        added=[
            CBOMDiffItem(
                name="AES-256-GCM",
                file="main.py",
                line=10,
                change_type=ChangeType.ADDED,
            ),
        ],
        removed=[],
        changed=[],
        unchanged_count=0,
    )

    with patch("app.api.v1.cbom.cbom_service.diff", new_callable=AsyncMock) as mock_diff:
        mock_diff.return_value = diff
        response = await client.get(
            "/api/v1/cbom/diff",
            params={"base": str(FAKE_SCAN_ID_1), "head": str(FAKE_SCAN_ID_2)},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["base_scan_id"] == str(FAKE_SCAN_ID_1)
    assert body["head_scan_id"] == str(FAKE_SCAN_ID_2)
    assert len(body["added"]) == 1
    assert body["added"][0]["name"] == "AES-256-GCM"
    assert body["added"][0]["change_type"] == "added"
    assert body["unchanged_count"] == 0

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/v1/cbom/merge
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_merge_endpoint(app, client: AsyncClient) -> None:
    """POST /api/v1/cbom/merge should return merged CBOM."""
    mock_session = AsyncMock()

    async def _override():
        yield mock_session

    app.dependency_overrides[get_session] = _override

    merged = MergedCBOM(
        project_ids=[FAKE_PROJECT_ID],
        total_components=2,
        components=[
            {"name": "AES-256-GCM", "type": "crypto-asset"},
            {"name": "RSA-2048", "type": "crypto-asset"},
        ],
    )

    with patch("app.api.v1.cbom.cbom_service.merge", new_callable=AsyncMock) as mock_merge:
        mock_merge.return_value = merged
        response = await client.post(
            "/api/v1/cbom/merge",
            json={"scan_ids": [str(FAKE_SCAN_ID_1), str(FAKE_SCAN_ID_2)]},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["total_components"] == 2
    assert len(body["components"]) == 2
    assert body["project_ids"] == [str(FAKE_PROJECT_ID)]

    app.dependency_overrides.clear()
