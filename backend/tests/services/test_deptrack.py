"""Tests for the Dependency-Track integration service — upload, retrieval, sync."""

import base64
import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services.deptrack_service import DepTrackService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dt_svc() -> DepTrackService:
    """Fresh DepTrackService with mocked persistence."""
    svc = DepTrackService()
    svc.configure(
        base_url="https://dt.example.com",
        api_key="test-api-key-123",
    )
    svc.set_store_connection(AsyncMock())
    svc.set_get_connection(
        AsyncMock(
            return_value={
                "base_url": "https://dt.example.com",
                "api_key": "test-api-key-123",
                "connected": True,
            }
        )
    )
    svc.set_get_cbom_for_scan(
        AsyncMock(
            return_value={
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {"type": "crypto-asset", "name": "AES-256-GCM"}
                ],
            }
        )
    )
    return svc


FAKE_CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:test-1234",
    "components": [
        {
            "type": "crypto-asset",
            "name": "AES-256-GCM",
            "cryptoProperties": {
                "algorithmProperties": {
                    "parameterSetIdentifier": "256",
                },
            },
        }
    ],
}

PROJECT_UUID = "550e8400-e29b-41d4-a716-446655440000"


def _mock_httpx_client(response_json, status_code=200):
    """Helper to build a mocked httpx.AsyncClient context manager."""
    mock_response = AsyncMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = response_json
    mock_response.text = json.dumps(response_json)
    mock_response.raise_for_status = AsyncMock()

    mock_client = AsyncMock()
    mock_client.put = AsyncMock(return_value=mock_response)
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    return mock_client


# ---------------------------------------------------------------------------
# CBOM upload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_cbom_sends_base64_encoded_bom(dt_svc: DepTrackService) -> None:
    """upload_cbom_to_deptrack() should PUT base64-encoded BOM to DT API."""
    mock_client = _mock_httpx_client({"token": "dt-token-abc"})

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.upload_cbom_to_deptrack(PROJECT_UUID, FAKE_CBOM)

        assert result["success"] is True
        assert result["token"] == "dt-token-abc"

        # Verify the payload was base64 encoded
        call_kwargs = mock_client.put.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["project"] == PROJECT_UUID
        decoded = json.loads(base64.b64decode(payload["bom"]))
        assert decoded["bomFormat"] == "CycloneDX"


@pytest.mark.asyncio
async def test_upload_cbom_returns_failure_on_http_error(dt_svc: DepTrackService) -> None:
    """upload_cbom_to_deptrack() should return success=False on HTTP errors."""
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.text = "Forbidden"

    import httpx as _httpx

    mock_response.raise_for_status = AsyncMock(
        side_effect=_httpx.HTTPStatusError(
            "Forbidden",
            request=_httpx.Request("PUT", "https://dt.example.com/api/v1/bom"),
            response=mock_response,
        )
    )

    mock_client = AsyncMock()
    mock_client.put = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.upload_cbom_to_deptrack(PROJECT_UUID, FAKE_CBOM)

        assert result["success"] is False
        assert "403" in result["message"]


@pytest.mark.asyncio
async def test_upload_cbom_handles_connection_error(dt_svc: DepTrackService) -> None:
    """upload_cbom_to_deptrack() should handle connection failures gracefully."""
    mock_client = AsyncMock()
    mock_client.put = AsyncMock(side_effect=ConnectionError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.upload_cbom_to_deptrack(PROJECT_UUID, FAKE_CBOM)

        assert result["success"] is False
        assert "connection error" in result["message"]


# ---------------------------------------------------------------------------
# Findings retrieval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_findings_returns_list(dt_svc: DepTrackService) -> None:
    """get_deptrack_findings() should return findings from DT API."""
    findings = [
        {"vulnerability": {"vulnId": "CVE-2024-1234"}, "component": {"name": "openssl"}},
        {"vulnerability": {"vulnId": "CVE-2024-5678"}, "component": {"name": "libcrypto"}},
    ]
    mock_client = _mock_httpx_client(findings)

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.get_deptrack_findings(PROJECT_UUID)

        assert len(result) == 2
        assert result[0]["vulnerability"]["vulnId"] == "CVE-2024-1234"
        mock_client.get.assert_called_once()


@pytest.mark.asyncio
async def test_get_findings_returns_empty_on_error(dt_svc: DepTrackService) -> None:
    """get_deptrack_findings() should return [] on HTTP errors."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=ConnectionError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.get_deptrack_findings(PROJECT_UUID)

        assert result == []


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_verifies_server(dt_svc: DepTrackService) -> None:
    """connect() should verify connectivity via the version endpoint."""
    mock_client = _mock_httpx_client({"version": "4.11.0", "application": "Dependency-Track"})

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.connect("https://dt.example.com", "test-key")

        assert result["connected"] is True
        assert "successfully" in result["message"].lower()
        dt_svc._store_connection.assert_called_once()


@pytest.mark.asyncio
async def test_connect_returns_failure_when_unreachable(dt_svc: DepTrackService) -> None:
    """connect() should return connected=False when server is unreachable."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=ConnectionError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.connect("https://dt.example.com", "bad-key")

        assert result["connected"] is False


@pytest.mark.asyncio
async def test_get_status_not_configured() -> None:
    """get_status() should return connected=False when not configured."""
    svc = DepTrackService()
    result = await svc.get_status()

    assert result["connected"] is False
    assert result["message"] == "Not configured"


@pytest.mark.asyncio
async def test_get_status_from_stored_connection(dt_svc: DepTrackService) -> None:
    """get_status() should load connection from storage and verify."""
    mock_client = _mock_httpx_client({"version": "4.11.0"})

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.get_status()

        assert result["connected"] is True
        assert result["server_version"] == "4.11.0"


# ---------------------------------------------------------------------------
# Sync scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_scan_uploads_cbom(dt_svc: DepTrackService) -> None:
    """sync_scan() should retrieve the CBOM and upload it to DT."""
    mock_client = _mock_httpx_client({"token": "sync-token-xyz"})

    with patch("app.services.deptrack_service.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client

        result = await dt_svc.sync_scan("scan-123", PROJECT_UUID)

        assert result["synced"] is True
        assert result["token"] == "sync-token-xyz"
        dt_svc._get_cbom_for_scan.assert_called_once_with("scan-123")


@pytest.mark.asyncio
async def test_sync_scan_no_cbom_found(dt_svc: DepTrackService) -> None:
    """sync_scan() should return synced=False when no CBOM exists for the scan."""
    dt_svc.set_get_cbom_for_scan(AsyncMock(return_value=None))

    result = await dt_svc.sync_scan("scan-999", PROJECT_UUID)

    assert result["synced"] is False
    assert "No CBOM found" in result["message"]


@pytest.mark.asyncio
async def test_sync_scan_no_cbom_callback() -> None:
    """sync_scan() should return synced=False when CBOM retrieval is not configured."""
    svc = DepTrackService()
    svc.configure("https://dt.example.com", "key")

    result = await svc.sync_scan("scan-123", PROJECT_UUID)

    assert result["synced"] is False
    assert "not configured" in result["message"].lower()


# ---------------------------------------------------------------------------
# Auth headers
# ---------------------------------------------------------------------------


def test_auth_headers_contain_api_key(dt_svc: DepTrackService) -> None:
    """_auth_headers() should include the X-Api-Key header."""
    headers = dt_svc._auth_headers()
    assert headers["X-Api-Key"] == "test-api-key-123"
    assert "Content-Type" in headers
