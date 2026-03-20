"""Tests for the CBOM signing service — sign + verify flow (mock cosign)."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.services.signing_service import SigningService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


FAKE_SCAN_ID = str(uuid.uuid4())
FAKE_CBOM = {
    "specVersion": "1.7",
    "components": [{"name": "AES-256-GCM", "type": "crypto-asset"}],
}
FAKE_SIGNATURE = "MEUCIQDfakebase64signatureAIhANfakebase64"
FAKE_REKOR_ID = "12345678"


@pytest.fixture
def signing_svc() -> SigningService:
    """Fresh SigningService with mocked persistence."""
    svc = SigningService()
    svc.set_store_signature(AsyncMock())
    svc.set_get_signature(
        AsyncMock(
            return_value={
                "signature": FAKE_SIGNATURE,
                "rekor_log_id": FAKE_REKOR_ID,
            }
        )
    )
    svc.set_get_cbom_json(AsyncMock(return_value=FAKE_CBOM))
    return svc


# ---------------------------------------------------------------------------
# Sign flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sign_cbom_success(signing_svc: SigningService) -> None:
    """sign_cbom() should return signed=True on successful cosign execution."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"",
                b"tlog entry created with index: 12345678\n",
            )
        )
        mock_exec.return_value = mock_proc

        # We need to also mock the sig file reading
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=FAKE_SIGNATURE):
            result = await signing_svc.sign_cbom(FAKE_SCAN_ID, FAKE_CBOM)

    assert result["signed"] is True
    assert result["signature"] == FAKE_SIGNATURE
    assert result["rekor_log_id"] == "12345678"
    signing_svc._store_signature.assert_called_once_with(
        FAKE_SCAN_ID, FAKE_SIGNATURE, "12345678"
    )


@pytest.mark.asyncio
async def test_sign_cbom_failure(signing_svc: SigningService) -> None:
    """sign_cbom() should return signed=False when cosign fails."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"cosign: error signing blob\n")
        )
        mock_exec.return_value = mock_proc

        result = await signing_svc.sign_cbom(FAKE_SCAN_ID, FAKE_CBOM)

    assert result["signed"] is False
    assert "error" in result
    signing_svc._store_signature.assert_not_called()


# ---------------------------------------------------------------------------
# Verify flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_cbom_success(signing_svc: SigningService) -> None:
    """verify_cbom() should return verified=True on successful cosign verify."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"Verified OK\n", b""))
        mock_exec.return_value = mock_proc

        result = await signing_svc.verify_cbom(FAKE_SCAN_ID)

    assert result["verified"] is True
    assert result["signature"] == FAKE_SIGNATURE
    assert result["rekor_log_id"] == FAKE_REKOR_ID


@pytest.mark.asyncio
async def test_verify_cbom_no_signature(signing_svc: SigningService) -> None:
    """verify_cbom() should return verified=False when no signature exists."""
    signing_svc.set_get_signature(AsyncMock(return_value=None))

    result = await signing_svc.verify_cbom(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_verify_cbom_no_cbom(signing_svc: SigningService) -> None:
    """verify_cbom() should return verified=False when CBOM is missing."""
    signing_svc.set_get_cbom_json(AsyncMock(return_value=None))

    result = await signing_svc.verify_cbom(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_verify_cbom_cosign_failure(signing_svc: SigningService) -> None:
    """verify_cbom() should return verified=False when cosign verify fails."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"Error: verification failed\n")
        )
        mock_exec.return_value = mock_proc

        result = await signing_svc.verify_cbom(FAKE_SCAN_ID)

    assert result["verified"] is False


# ---------------------------------------------------------------------------
# No backend configured
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_cbom_no_backend() -> None:
    """verify_cbom() should return error when no backend is configured."""
    svc = SigningService()
    result = await svc.verify_cbom(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not configured" in result["error"].lower()
