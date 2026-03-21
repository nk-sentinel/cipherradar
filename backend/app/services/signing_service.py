"""CBOM signing service — sign and verify CBOMs using cosign.

Uses the cosign CLI as a subprocess for keyless signing (Sigstore)
and stores the signature + Rekor log entry ID alongside the CBOM.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class SigningService:
    """Sign and verify CycloneDX CBOM documents using cosign."""

    def __init__(self) -> None:
        # Pluggable persistence callbacks
        self._store_signature = None  # async (scan_id, signature, rekor_log_id) -> None
        self._get_signature = None  # async (scan_id) -> dict | None
        self._get_cbom_json = None  # async (scan_id) -> dict | None

    # -- DI setters ---------------------------------------------------------

    def set_store_signature(self, fn) -> None:  # noqa: ANN001
        self._store_signature = fn

    def set_get_signature(self, fn) -> None:  # noqa: ANN001
        self._get_signature = fn

    def set_get_cbom_json(self, fn) -> None:  # noqa: ANN001
        self._get_cbom_json = fn

    # -- Sign ---------------------------------------------------------------

    async def sign_cbom(self, scan_id: str, cbom_json: dict) -> dict:
        """Sign a CBOM document using cosign keyless signing.

        Args:
            scan_id: Scan UUID string.
            cbom_json: The CycloneDX CBOM JSON dict to sign.

        Returns:
            Dict with ``signature``, ``rekor_log_id``, ``signed`` (bool).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            cbom_path = Path(tmpdir) / "cbom.json"
            sig_path = Path(tmpdir) / "cbom.sig"

            cbom_path.write_text(json.dumps(cbom_json, indent=2))

            # cosign sign-blob --yes --output-signature sig_path cbom_path
            proc = await asyncio.create_subprocess_exec(
                "cosign",
                "sign-blob",
                "--yes",
                "--output-signature",
                str(sig_path),
                str(cbom_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Unknown cosign error"
                logger.warning("cosign sign-blob failed for scan %s: %s", scan_id, error_msg)
                return {"signed": False, "error": error_msg}

            signature = sig_path.read_text().strip() if sig_path.exists() else ""

            # Extract Rekor log entry ID from stderr (cosign outputs it there)
            rekor_log_id = ""
            stderr_text = stderr.decode() if stderr else ""
            for line in stderr_text.splitlines():
                if "tlog entry created with index:" in line.lower():
                    rekor_log_id = line.split(":")[-1].strip()
                    break

        if self._store_signature is not None:
            await self._store_signature(scan_id, signature, rekor_log_id)

        return {
            "signed": True,
            "signature": signature,
            "rekor_log_id": rekor_log_id,
        }

    # -- Verify -------------------------------------------------------------

    async def verify_cbom(self, scan_id: str) -> dict:
        """Verify a CBOM signature using cosign.

        Args:
            scan_id: Scan UUID string.

        Returns:
            Dict with ``verified`` (bool) and detail fields.
        """
        # Load stored signature
        if self._get_signature is None:
            return {"verified": False, "error": "Signing backend not configured"}

        sig_record = await self._get_signature(scan_id)
        if sig_record is None:
            return {"verified": False, "error": "Signature not found for this CBOM"}

        # Load CBOM JSON
        if self._get_cbom_json is None:
            return {"verified": False, "error": "CBOM backend not configured"}

        cbom_json = await self._get_cbom_json(scan_id)
        if cbom_json is None:
            return {"verified": False, "error": "CBOM not found"}

        with tempfile.TemporaryDirectory() as tmpdir:
            cbom_path = Path(tmpdir) / "cbom.json"
            sig_path = Path(tmpdir) / "cbom.sig"

            cbom_path.write_text(json.dumps(cbom_json, indent=2))
            sig_path.write_text(sig_record.get("signature", ""))

            proc = await asyncio.create_subprocess_exec(
                "cosign",
                "verify-blob",
                "--signature",
                str(sig_path),
                str(cbom_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Verification failed"
                return {"verified": False, "error": error_msg}

        return {
            "verified": True,
            "signature": sig_record.get("signature", ""),
            "rekor_log_id": sig_record.get("rekor_log_id", ""),
        }


# Module-level singleton
signing_service = SigningService()
