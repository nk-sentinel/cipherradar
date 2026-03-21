"""Tests for the CBOM attestation API endpoints."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_SCAN_ID = uuid.uuid4()


def _make_stored_attestation(scan_id: uuid.UUID = FAKE_SCAN_ID) -> dict:
    """Build a mock stored attestation record."""
    return {
        "scan_id": str(scan_id),
        "attested": True,
        "signature": "FAKESIG",
        "certificate": "FAKECERT",
        "rekor_log_id": "12345",
        "in_toto_statement": {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "cbom.json",
                    "digest": {"sha256": "abc123"},
                },
            ],
            "predicateType": "https://cipherradar.dev/attestation/cbom/v1",
            "predicate": {
                "scanner": "cradar",
                "version": "0.1.0",
                "timestamp": "2026-03-22T12:00:00+00:00",
                "findings_count": 382,
                "quantum_risk_score": 58,
                "compliance": {"nist": 72, "fips": 65},
            },
        },
        "signed_at": "2026-03-22T12:00:00+00:00",
        "signer_identity": "test@cipherradar.dev",
    }


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
# GET /api/v1/scans/{scan_id}/attestation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_attestation_returns_200(app, client: AsyncClient) -> None:
    """GET attestation should return 200 with metadata when attestation exists."""
    with patch(
        "app.api.v1.attestation.attestation_service.get_attestation_metadata",
        new_callable=AsyncMock,
    ) as mock_meta:
        mock_meta.return_value = {
            "scan_id": str(FAKE_SCAN_ID),
            "signer_identity": "test@cipherradar.dev",
            "signed_at": "2026-03-22T12:00:00+00:00",
            "rekor_log_id": "12345",
            "certificate": "FAKECERT",
            "certificate_chain": ["FAKECERT"],
            "in_toto_statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {"name": "cbom.json", "digest": {"sha256": "abc123"}},
                ],
                "predicateType": "https://cipherradar.dev/attestation/cbom/v1",
                "predicate": {
                    "scanner": "cradar",
                    "version": "0.1.0",
                    "timestamp": "2026-03-22T12:00:00+00:00",
                    "findings_count": 382,
                    "quantum_risk_score": 58,
                    "compliance": {"nist": 72, "fips": 65},
                },
            },
        }

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation")

    assert response.status_code == 200
    body = response.json()
    assert body["scanId"] == str(FAKE_SCAN_ID)
    assert body["signerIdentity"] == "test@cipherradar.dev"
    assert body["rekorLogId"] == "12345"
    assert body["inTotoStatement"] is not None
    assert body["inTotoStatement"]["predicateType"] == "https://cipherradar.dev/attestation/cbom/v1"


@pytest.mark.asyncio
async def test_get_attestation_returns_404_when_not_found(app, client: AsyncClient) -> None:
    """GET attestation should return 404 when no attestation exists."""
    with patch(
        "app.api.v1.attestation.attestation_service.get_attestation_metadata",
        new_callable=AsyncMock,
    ) as mock_meta:
        mock_meta.return_value = {"error": "Attestation not found for this scan"}

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/attestation/verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_attestation_returns_200(app, client: AsyncClient) -> None:
    """GET verify should return 200 with verification result."""
    with patch(
        "app.api.v1.attestation.attestation_service.verify_attestation",
        new_callable=AsyncMock,
    ) as mock_verify:
        mock_verify.return_value = {
            "scan_id": str(FAKE_SCAN_ID),
            "verified": True,
            "signer_identity": "test@cipherradar.dev",
            "timestamp": "2026-03-22T12:00:00+00:00",
            "rekor_log_id": "12345",
        }

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["signerIdentity"] == "test@cipherradar.dev"
    assert body["rekorLogId"] == "12345"


@pytest.mark.asyncio
async def test_verify_attestation_returns_200_with_error(app, client: AsyncClient) -> None:
    """GET verify should return 200 with verified=False on verification failure."""
    with patch(
        "app.api.v1.attestation.attestation_service.verify_attestation",
        new_callable=AsyncMock,
    ) as mock_verify:
        mock_verify.return_value = {
            "scan_id": str(FAKE_SCAN_ID),
            "verified": False,
            "error": "Signature mismatch",
        }

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is False
    assert body["error"] == "Signature mismatch"


@pytest.mark.asyncio
async def test_verify_attestation_returns_404_when_not_found(app, client: AsyncClient) -> None:
    """GET verify should return 404 when attestation not found."""
    with patch(
        "app.api.v1.attestation.attestation_service.verify_attestation",
        new_callable=AsyncMock,
    ) as mock_verify:
        mock_verify.return_value = {
            "scan_id": str(FAKE_SCAN_ID),
            "verified": False,
            "error": "Attestation not found for this scan",
        }

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation/verify")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/attestation/download
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_attestation_returns_200(app, client: AsyncClient) -> None:
    """GET download should return 200 with a Sigstore bundle."""
    with patch(
        "app.api.v1.attestation.attestation_service.get_attestation_metadata",
        new_callable=AsyncMock,
    ) as mock_meta:
        mock_meta.return_value = {
            "scan_id": str(FAKE_SCAN_ID),
            "signer_identity": "test@cipherradar.dev",
            "signed_at": "2026-03-22T12:00:00+00:00",
            "rekor_log_id": "12345",
            "certificate": "FAKECERT",
            "certificate_chain": ["FAKECERT"],
            "in_toto_statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {"name": "cbom.json", "digest": {"sha256": "abc123"}},
                ],
                "predicateType": "https://cipherradar.dev/attestation/cbom/v1",
                "predicate": {
                    "scanner": "cradar",
                    "version": "0.1.0",
                    "timestamp": "2026-03-22T12:00:00+00:00",
                    "findings_count": 382,
                    "quantum_risk_score": 58,
                    "compliance": {"nist": 72, "fips": 65},
                },
            },
        }

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation/download")

    assert response.status_code == 200
    body = response.json()
    assert body["scanId"] == str(FAKE_SCAN_ID)
    assert "bundle" in body
    bundle = body["bundle"]
    assert bundle["mediaType"] == "application/vnd.dev.sigstore.bundle+json;version=0.3"
    assert "verificationMaterial" in bundle
    assert "dsseEnvelope" in bundle


@pytest.mark.asyncio
async def test_download_attestation_returns_404_when_not_found(app, client: AsyncClient) -> None:
    """GET download should return 404 when attestation not found."""
    with patch(
        "app.api.v1.attestation.attestation_service.get_attestation_metadata",
        new_callable=AsyncMock,
    ) as mock_meta:
        mock_meta.return_value = {"error": "Attestation not found for this scan"}

        response = await client.get(f"/api/v1/scans/{FAKE_SCAN_ID}/attestation/download")

    assert response.status_code == 404
