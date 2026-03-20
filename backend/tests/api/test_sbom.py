"""Tests for SBOM API endpoints."""

import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.schemas.sbom import SBOMCBOMLink, SBOMCBOMLinkResponse, SBOMUploadResponse

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


@pytest.mark.asyncio
async def test_upload_sbom_cyclonedx(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()

    sbom_id = uuid.uuid4()
    fake_response = SBOMUploadResponse(
        sbom_id=sbom_id,
        project_id=FAKE_PROJECT_ID,
        format="cyclonedx",
        components_count=3,
        storage_uri=f"postgres://{sbom_id}",
    )

    with patch(
        "app.api.v1.sbom.sbom_service.upload_sbom",
        new_callable=AsyncMock,
        return_value=fake_response,
    ):
        sbom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "openssl", "version": "3.0.2"},
                {"name": "libsodium", "version": "1.0.18"},
                {"name": "boringssl", "version": "0.0.0"},
            ],
        }
        response = await client.post(
            f"/api/v1/sbom/upload?project_id={FAKE_PROJECT_ID}",
            content=json.dumps(sbom_json),
        )

    assert response.status_code == 201
    body = response.json()
    assert body["format"] == "cyclonedx"
    assert body["components_count"] == 3

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_sbom_cbom_link(app, client: AsyncClient) -> None:
    app.dependency_overrides[get_session] = _mock_session_override()

    fake_response = SBOMCBOMLinkResponse(
        project_id=FAKE_PROJECT_ID,
        total_libraries=3,
        linked_libraries=1,
        links=[
            SBOMCBOMLink(
                library_name="openssl",
                library_version="3.0.2",
                purl="pkg:generic/openssl@3.0.2",
                crypto_findings=["AES-256-GCM via OpenSSL"],
                findings_count=1,
            ),
            SBOMCBOMLink(library_name="react", library_version="19.0.0"),
            SBOMCBOMLink(library_name="lodash", library_version="4.17.21"),
        ],
    )

    with patch(
        "app.api.v1.sbom.sbom_service.get_sbom_cbom_links",
        new_callable=AsyncMock,
        return_value=fake_response,
    ):
        response = await client.get(f"/api/v1/projects/{FAKE_PROJECT_ID}/sbom-cbom-link")

    assert response.status_code == 200
    body = response.json()
    assert body["total_libraries"] == 3
    assert body["linked_libraries"] == 1
    assert len(body["links"]) == 3
    assert body["links"][0]["library_name"] == "openssl"
    assert body["links"][0]["findings_count"] == 1

    app.dependency_overrides.clear()
