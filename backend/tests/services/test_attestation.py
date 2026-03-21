"""Tests for the CBOM attestation service — create, verify, metadata (mock cosign)."""

import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.services.attestation_service import AttestationService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_SCAN_ID = uuid.uuid4()
FAKE_CBOM = json.dumps(
    {
        "specVersion": "1.7",
        "components": [{"name": "AES-256-GCM", "type": "crypto-asset"}],
    },
    indent=2,
).encode()
FAKE_SIGNATURE = "MEUCIQDfakebase64attestsigAIhANfakebase64"
FAKE_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----"
FAKE_REKOR_ID = "87654321"


def _make_stored_attestation() -> dict:
    """Build a mock stored attestation record."""
    return {
        "scan_id": str(FAKE_SCAN_ID),
        "attested": True,
        "signature": FAKE_SIGNATURE,
        "certificate": FAKE_CERTIFICATE,
        "rekor_log_id": FAKE_REKOR_ID,
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
def attest_svc() -> AttestationService:
    """Fresh AttestationService with mocked persistence."""
    svc = AttestationService()
    svc.set_store_attestation(AsyncMock())
    svc.set_get_attestation(AsyncMock(return_value=_make_stored_attestation()))
    svc.set_get_cbom_json(AsyncMock(return_value=FAKE_CBOM))
    return svc


# ---------------------------------------------------------------------------
# build_in_toto_statement (pure, no subprocess)
# ---------------------------------------------------------------------------


def test_build_in_toto_statement() -> None:
    """build_in_toto_statement should produce a valid in-toto v1 dict."""
    statement = AttestationService.build_in_toto_statement(
        "deadbeef" * 8,
        findings_count=42,
        quantum_risk_score=75,
        compliance={"nist": 90},
    )

    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert len(statement["subject"]) == 1
    assert statement["subject"][0]["name"] == "cbom.json"
    assert statement["subject"][0]["digest"]["sha256"] == "deadbeef" * 8
    assert statement["predicateType"] == "https://cipherradar.dev/attestation/cbom/v1"
    assert statement["predicate"]["scanner"] == "cradar"
    assert statement["predicate"]["findings_count"] == 42
    assert statement["predicate"]["quantum_risk_score"] == 75
    assert statement["predicate"]["compliance"] == {"nist": 90}


def test_build_in_toto_statement_defaults() -> None:
    """build_in_toto_statement should use sane defaults."""
    statement = AttestationService.build_in_toto_statement("abc123")
    assert statement["predicate"]["findings_count"] == 0
    assert statement["predicate"]["quantum_risk_score"] == 0
    assert statement["predicate"]["compliance"] == {}


# ---------------------------------------------------------------------------
# create_attestation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_attestation_success(attest_svc: AttestationService) -> None:
    """create_attestation should return attested=True on successful cosign execution."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"",
                b"tlog entry created with index: 87654321\n",
            )
        )
        mock_exec.return_value = mock_proc

        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=[FAKE_SIGNATURE, FAKE_CERTIFICATE]):
            result = await attest_svc.create_attestation(
                FAKE_SCAN_ID,
                FAKE_CBOM,
                findings_count=382,
                quantum_risk_score=58,
                compliance={"nist": 72, "fips": 65},
            )

    assert result["attested"] is True
    assert result["signature"] == FAKE_SIGNATURE
    assert result["certificate"] == FAKE_CERTIFICATE
    assert result["rekor_log_id"] == "87654321"
    assert result["in_toto_statement"]["_type"] == "https://in-toto.io/Statement/v1"
    assert result["in_toto_statement"]["predicate"]["findings_count"] == 382
    attest_svc._store_attestation.assert_called_once()


@pytest.mark.asyncio
async def test_create_attestation_cosign_failure(attest_svc: AttestationService) -> None:
    """create_attestation should return attested=False when cosign fails."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"cosign: error attesting blob\n")
        )
        mock_exec.return_value = mock_proc

        result = await attest_svc.create_attestation(FAKE_SCAN_ID, FAKE_CBOM)

    assert result["attested"] is False
    assert "error" in result
    attest_svc._store_attestation.assert_not_called()


@pytest.mark.asyncio
async def test_create_attestation_stores_data(attest_svc: AttestationService) -> None:
    """create_attestation should call the store callback with attestation data."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_exec.return_value = mock_proc

        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="sig"):
            await attest_svc.create_attestation(FAKE_SCAN_ID, FAKE_CBOM)

    attest_svc._store_attestation.assert_called_once()
    call_args = attest_svc._store_attestation.call_args
    stored_scan_id = call_args[0][0]
    stored_data = call_args[0][1]
    assert stored_scan_id == str(FAKE_SCAN_ID)
    assert stored_data["attested"] is True
    assert "in_toto_statement" in stored_data


# ---------------------------------------------------------------------------
# verify_attestation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_attestation_success(attest_svc: AttestationService) -> None:
    """verify_attestation should return verified=True on successful cosign verify."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"Verified OK\n", b""))
        mock_exec.return_value = mock_proc

        result = await attest_svc.verify_attestation(FAKE_SCAN_ID)

    assert result["verified"] is True
    assert result["signer_identity"] == "test@cipherradar.dev"
    assert result["rekor_log_id"] == FAKE_REKOR_ID


@pytest.mark.asyncio
async def test_verify_attestation_not_found(attest_svc: AttestationService) -> None:
    """verify_attestation should return verified=False when attestation not stored."""
    attest_svc.set_get_attestation(AsyncMock(return_value=None))

    result = await attest_svc.verify_attestation(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_verify_attestation_no_cbom(attest_svc: AttestationService) -> None:
    """verify_attestation should return verified=False when CBOM is missing."""
    attest_svc.set_get_cbom_json(AsyncMock(return_value=None))

    result = await attest_svc.verify_attestation(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_verify_attestation_cosign_failure(attest_svc: AttestationService) -> None:
    """verify_attestation should return verified=False when cosign verify fails."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"Error: verification failed\n")
        )
        mock_exec.return_value = mock_proc

        result = await attest_svc.verify_attestation(FAKE_SCAN_ID)

    assert result["verified"] is False


@pytest.mark.asyncio
async def test_verify_attestation_no_backend() -> None:
    """verify_attestation should return error when no backend is configured."""
    svc = AttestationService()
    result = await svc.verify_attestation(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not configured" in result["error"].lower()


@pytest.mark.asyncio
async def test_verify_attestation_no_cbom_backend() -> None:
    """verify_attestation should error when cbom backend missing."""
    svc = AttestationService()
    svc.set_get_attestation(AsyncMock(return_value=_make_stored_attestation()))
    result = await svc.verify_attestation(FAKE_SCAN_ID)

    assert result["verified"] is False
    assert "not configured" in result["error"].lower()


# ---------------------------------------------------------------------------
# get_attestation_metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_attestation_metadata_success(attest_svc: AttestationService) -> None:
    """get_attestation_metadata should return full metadata."""
    result = await attest_svc.get_attestation_metadata(FAKE_SCAN_ID)

    assert result["scan_id"] == str(FAKE_SCAN_ID)
    assert result["signer_identity"] == "test@cipherradar.dev"
    assert result["rekor_log_id"] == FAKE_REKOR_ID
    assert result["certificate"] == FAKE_CERTIFICATE
    assert len(result["certificate_chain"]) == 1
    assert result["in_toto_statement"] is not None
    assert result["in_toto_statement"]["_type"] == "https://in-toto.io/Statement/v1"


@pytest.mark.asyncio
async def test_get_attestation_metadata_not_found(attest_svc: AttestationService) -> None:
    """get_attestation_metadata should return error when attestation not found."""
    attest_svc.set_get_attestation(AsyncMock(return_value=None))

    result = await attest_svc.get_attestation_metadata(FAKE_SCAN_ID)

    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_get_attestation_metadata_no_backend() -> None:
    """get_attestation_metadata should error when backend not configured."""
    svc = AttestationService()
    result = await svc.get_attestation_metadata(FAKE_SCAN_ID)

    assert "error" in result
    assert "not configured" in result["error"].lower()


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------


def test_compute_sha256() -> None:
    """_compute_sha256 should return correct hex digest."""
    import hashlib

    data = b"hello world"
    expected = hashlib.sha256(data).hexdigest()
    assert AttestationService._compute_sha256(data) == expected
