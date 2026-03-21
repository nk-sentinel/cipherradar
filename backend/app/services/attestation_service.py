"""CBOM attestation service — create and verify Sigstore in-toto attestations.

Uses cosign attest-blob / verify-blob-attestation with in-toto predicate format.
Stores: signature, certificate, Rekor log entry ID, in-toto statement.
"""

import asyncio
import hashlib
import json
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

logger = logging.getLogger(__name__)

# Scanner metadata
SCANNER_NAME = "cradar"
SCANNER_VERSION = "0.1.0"

# In-toto predicate type for CipherRadar CBOM attestations
PREDICATE_TYPE = "https://cipherradar.dev/attestation/cbom/v1"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def _signing_enabled() -> bool:
    """Check if CBOM signing/attestation is enabled via environment."""
    return os.environ.get("CRADAR_SIGNING_ENABLED", "false").lower() == "true"


class AttestationService:
    """Create and verify Sigstore in-toto attestations for CBOM scan results."""

    def __init__(self) -> None:
        # Pluggable persistence callbacks
        self._store_attestation = None  # async (scan_id, attestation_data) -> None
        self._get_attestation = None  # async (scan_id) -> dict | None
        self._get_cbom_json = None  # async (scan_id) -> bytes | None

    # -- DI setters ---------------------------------------------------------

    def set_store_attestation(self, fn) -> None:  # noqa: ANN001
        self._store_attestation = fn

    def set_get_attestation(self, fn) -> None:  # noqa: ANN001
        self._get_attestation = fn

    def set_get_cbom_json(self, fn) -> None:  # noqa: ANN001
        self._get_cbom_json = fn

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _compute_sha256(data: bytes) -> str:
        """Compute SHA-256 hex digest of raw bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def build_in_toto_statement(
        cbom_sha256: str,
        *,
        findings_count: int = 0,
        quantum_risk_score: int = 0,
        compliance: dict[str, int] | None = None,
    ) -> dict:
        """Build an in-toto v1 statement dict for a CBOM attestation.

        Args:
            cbom_sha256: SHA-256 hex digest of the CBOM JSON bytes.
            findings_count: Number of crypto findings in the scan.
            quantum_risk_score: Aggregate quantum risk score (0-100).
            compliance: Framework compliance scores, e.g. {"nist": 72, "fips": 65}.

        Returns:
            Dict conforming to the in-toto Statement v1 spec.
        """
        return {
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": [
                {
                    "name": "cbom.json",
                    "digest": {"sha256": cbom_sha256},
                },
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "scanner": SCANNER_NAME,
                "version": SCANNER_VERSION,
                "timestamp": datetime.now(UTC).isoformat(),
                "findings_count": findings_count,
                "quantum_risk_score": quantum_risk_score,
                "compliance": compliance or {},
            },
        }

    # -- Create attestation -------------------------------------------------

    async def create_attestation(
        self,
        scan_id: UUID,
        cbom_json: bytes,
        *,
        findings_count: int = 0,
        quantum_risk_score: int = 0,
        compliance: dict[str, int] | None = None,
    ) -> dict:
        """Create a Sigstore attestation for a CBOM scan result.

        Uses cosign attest-blob with in-toto predicate format.
        Stores: signature, certificate, Rekor log entry ID, in-toto statement.

        Args:
            scan_id: UUID of the scan.
            cbom_json: Raw CBOM JSON bytes.
            findings_count: Number of findings detected.
            quantum_risk_score: Aggregate quantum risk score.
            compliance: Dict of framework compliance scores.

        Returns:
            Dict with attested (bool), signature, certificate, rekor_log_id,
            in_toto_statement, and optionally error.
        """
        cbom_sha256 = self._compute_sha256(cbom_json)
        statement = self.build_in_toto_statement(
            cbom_sha256,
            findings_count=findings_count,
            quantum_risk_score=quantum_risk_score,
            compliance=compliance,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cbom_path = Path(tmpdir) / "cbom.json"
            statement_path = Path(tmpdir) / "statement.json"
            sig_path = Path(tmpdir) / "cbom.sig"
            cert_path = Path(tmpdir) / "cbom.cert"

            cbom_path.write_bytes(cbom_json)
            statement_path.write_text(json.dumps(statement, indent=2))

            # cosign attest-blob with in-toto predicate
            proc = await asyncio.create_subprocess_exec(
                "cosign",
                "attest-blob",
                "--yes",
                "--predicate",
                str(statement_path),
                "--type",
                PREDICATE_TYPE,
                "--output-signature",
                str(sig_path),
                "--output-certificate",
                str(cert_path),
                str(cbom_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Unknown cosign error"
                logger.warning("cosign attest-blob failed for scan %s: %s", scan_id, error_msg)
                return {
                    "scan_id": str(scan_id),
                    "attested": False,
                    "error": error_msg,
                }

            signature = sig_path.read_text().strip() if sig_path.exists() else ""
            certificate = cert_path.read_text().strip() if cert_path.exists() else ""

            # Extract Rekor log entry ID from stderr
            rekor_log_id = ""
            stderr_text = stderr.decode() if stderr else ""
            for line in stderr_text.splitlines():
                if "tlog entry created with index:" in line.lower():
                    rekor_log_id = line.split(":")[-1].strip()
                    break

        attestation_data = {
            "scan_id": str(scan_id),
            "attested": True,
            "signature": signature,
            "certificate": certificate,
            "rekor_log_id": rekor_log_id,
            "in_toto_statement": statement,
            "signed_at": datetime.now(UTC).isoformat(),
            "signer_identity": "",
        }

        if self._store_attestation is not None:
            await self._store_attestation(str(scan_id), attestation_data)

        return attestation_data

    # -- Verify attestation -------------------------------------------------

    async def verify_attestation(self, scan_id: UUID) -> dict:
        """Verify a CBOM attestation via cosign verify-blob-attestation.

        Args:
            scan_id: UUID of the scan.

        Returns:
            Dict with verified (bool), signer_identity, timestamp,
            rekor_log_id, and optionally error.
        """
        if self._get_attestation is None:
            return {
                "scan_id": str(scan_id),
                "verified": False,
                "error": "Attestation backend not configured",
            }

        attestation = await self._get_attestation(str(scan_id))
        if attestation is None:
            return {
                "scan_id": str(scan_id),
                "verified": False,
                "error": "Attestation not found for this scan",
            }

        if self._get_cbom_json is None:
            return {
                "scan_id": str(scan_id),
                "verified": False,
                "error": "CBOM backend not configured",
            }

        cbom_json = await self._get_cbom_json(str(scan_id))
        if cbom_json is None:
            return {
                "scan_id": str(scan_id),
                "verified": False,
                "error": "CBOM not found",
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            cbom_path = Path(tmpdir) / "cbom.json"
            sig_path = Path(tmpdir) / "cbom.sig"
            cert_path = Path(tmpdir) / "cbom.cert"

            cbom_path.write_bytes(cbom_json if isinstance(cbom_json, bytes) else cbom_json.encode())
            sig_path.write_text(attestation.get("signature", ""))
            cert_path.write_text(attestation.get("certificate", ""))

            cmd = [
                "cosign",
                "verify-blob-attestation",
                "--signature",
                str(sig_path),
                "--certificate",
                str(cert_path),
                "--type",
                PREDICATE_TYPE,
                str(cbom_path),
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Verification failed"
                return {
                    "scan_id": str(scan_id),
                    "verified": False,
                    "error": error_msg,
                }

        return {
            "scan_id": str(scan_id),
            "verified": True,
            "signer_identity": attestation.get("signer_identity", ""),
            "timestamp": attestation.get("signed_at", ""),
            "rekor_log_id": attestation.get("rekor_log_id", ""),
        }

    # -- Get attestation metadata -------------------------------------------

    async def get_attestation_metadata(self, scan_id: UUID) -> dict:
        """Get attestation details for a scan.

        Returns signer identity, timestamp, Rekor entry, certificate chain,
        and the full in-toto statement.

        Args:
            scan_id: UUID of the scan.

        Returns:
            Dict with attestation metadata, or error if not found.
        """
        if self._get_attestation is None:
            return {"error": "Attestation backend not configured"}

        attestation = await self._get_attestation(str(scan_id))
        if attestation is None:
            return {"error": "Attestation not found for this scan"}

        certificate = attestation.get("certificate", "")
        certificate_chain = []
        if certificate:
            certificate_chain = [certificate]

        return {
            "scan_id": str(scan_id),
            "signer_identity": attestation.get("signer_identity", ""),
            "signed_at": attestation.get("signed_at"),
            "rekor_log_id": attestation.get("rekor_log_id", ""),
            "certificate": certificate,
            "certificate_chain": certificate_chain,
            "in_toto_statement": attestation.get("in_toto_statement"),
        }


# Module-level singleton
attestation_service = AttestationService()
