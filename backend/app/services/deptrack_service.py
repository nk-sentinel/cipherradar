"""Dependency-Track integration service — CBOM upload and findings retrieval.

Uploads CycloneDX CBOM documents to Dependency-Track via its REST API and
retrieves vulnerability findings for correlation with CipherRadar results.
"""

import base64
import json
import logging

import httpx

logger = logging.getLogger(__name__)


class DepTrackService:
    """Manages Dependency-Track API interactions for CBOM upload and findings retrieval."""

    def __init__(self) -> None:
        # Pluggable persistence callbacks — set by the app layer or tests.
        self._store_connection = None  # async (record: dict) -> None
        self._get_connection = None  # async () -> dict | None
        self._get_cbom_for_scan = None  # async (scan_id: str) -> dict | None

        # Connection details (set via connect or from stored config)
        self.base_url: str = ""
        self.api_key: str = ""

    # -- DI setters ---------------------------------------------------------

    def set_store_connection(self, fn) -> None:  # noqa: ANN001
        """Register async callback ``(record: dict) -> None``."""
        self._store_connection = fn

    def set_get_connection(self, fn) -> None:  # noqa: ANN001
        """Register async callback ``() -> dict | None``."""
        self._get_connection = fn

    def set_get_cbom_for_scan(self, fn) -> None:  # noqa: ANN001
        """Register async callback ``(scan_id: str) -> dict | None``."""
        self._get_cbom_for_scan = fn

    def configure(self, base_url: str, api_key: str) -> None:
        """Set Dependency-Track connection details."""
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    # -- Connection management ----------------------------------------------

    async def connect(self, base_url: str, api_key: str) -> dict:
        """Save and verify a Dependency-Track connection.

        Returns:
            Connection record dict with ``connected``, ``base_url``, ``message``.
        """
        self.configure(base_url, api_key)

        # Verify connectivity by calling the version endpoint
        version_info = await self._get_server_version()
        connected = version_info is not None

        record = {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "connected": connected,
            "server_version": version_info.get("version", "") if version_info else "",
        }

        if self._store_connection is not None:
            await self._store_connection(record)

        return {
            "connected": connected,
            "base_url": self.base_url,
            "message": "Connected successfully" if connected else "Failed to connect to Dependency-Track",
        }

    async def get_status(self) -> dict:
        """Return the current Dependency-Track connection status."""
        if self._get_connection is not None:
            connection = await self._get_connection()
            if connection is not None:
                self.configure(connection["base_url"], connection["api_key"])
                version_info = await self._get_server_version()
                return {
                    "connected": version_info is not None,
                    "base_url": self.base_url,
                    "server_version": version_info.get("version", "") if version_info else "",
                    "message": "Connected" if version_info else "Connection failed",
                }

        if self.base_url and self.api_key:
            version_info = await self._get_server_version()
            return {
                "connected": version_info is not None,
                "base_url": self.base_url,
                "server_version": version_info.get("version", "") if version_info else "",
                "message": "Connected" if version_info else "Connection failed",
            }

        return {
            "connected": False,
            "base_url": "",
            "server_version": "",
            "message": "Not configured",
        }

    # -- CBOM upload --------------------------------------------------------

    async def upload_cbom_to_deptrack(self, project_uuid: str, cbom_json: dict) -> dict:
        """Upload a CBOM document to Dependency-Track.

        Uses ``PUT /api/v1/bom`` with the CBOM encoded as base64.

        Args:
            project_uuid: Dependency-Track project UUID.
            cbom_json: CycloneDX CBOM JSON document.

        Returns:
            Dict with ``success``, ``token`` (DT processing token), and ``message``.
        """
        bom_base64 = base64.b64encode(json.dumps(cbom_json).encode()).decode()

        payload = {
            "project": project_uuid,
            "bom": bom_base64,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.put(
                    f"{self.base_url}/api/v1/bom",
                    json=payload,
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                result = resp.json()

            return {
                "success": True,
                "token": result.get("token", ""),
                "message": "CBOM uploaded successfully",
            }
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Dependency-Track CBOM upload failed (HTTP %s): %s",
                exc.response.status_code,
                exc.response.text,
            )
            return {
                "success": False,
                "token": "",
                "message": f"Upload failed: HTTP {exc.response.status_code}",
            }
        except Exception:
            logger.warning("Dependency-Track CBOM upload failed", exc_info=True)
            return {
                "success": False,
                "token": "",
                "message": "Upload failed: connection error",
            }

    # -- Findings retrieval -------------------------------------------------

    async def get_deptrack_findings(self, project_uuid: str) -> list[dict]:
        """Retrieve vulnerability findings from Dependency-Track for a project.

        Uses ``GET /api/v1/finding/project/{uuid}``.

        Args:
            project_uuid: Dependency-Track project UUID.

        Returns:
            List of finding dicts from Dependency-Track.
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.base_url}/api/v1/finding/project/{project_uuid}",
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Dependency-Track findings retrieval failed (HTTP %s)",
                exc.response.status_code,
            )
            return []
        except Exception:
            logger.warning("Dependency-Track findings retrieval failed", exc_info=True)
            return []

    # -- Sync from scan -----------------------------------------------------

    async def sync_scan(self, scan_id: str, project_uuid: str) -> dict:
        """Sync a CipherRadar scan's CBOM to Dependency-Track.

        Retrieves the CBOM for the given scan and uploads it.

        Args:
            scan_id: CipherRadar scan ID.
            project_uuid: Dependency-Track project UUID.

        Returns:
            Dict with ``synced``, ``project_uuid``, ``token``, ``message``.
        """
        if self._get_cbom_for_scan is None:
            return {
                "synced": False,
                "project_uuid": project_uuid,
                "token": "",
                "message": "CBOM retrieval not configured",
            }

        cbom_json = await self._get_cbom_for_scan(scan_id)
        if cbom_json is None:
            return {
                "synced": False,
                "project_uuid": project_uuid,
                "token": "",
                "message": f"No CBOM found for scan {scan_id}",
            }

        result = await self.upload_cbom_to_deptrack(project_uuid, cbom_json)
        return {
            "synced": result["success"],
            "project_uuid": project_uuid,
            "token": result.get("token", ""),
            "message": result["message"],
        }

    # -- Internal helpers ---------------------------------------------------

    async def _get_server_version(self) -> dict | None:
        """Fetch Dependency-Track server version for health check.

        Returns:
            Version info dict or None if unreachable.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.base_url}/api/version",
                    headers=self._auth_headers(),
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            logger.debug("Dependency-Track version check failed", exc_info=True)
            return None

    def _auth_headers(self) -> dict[str, str]:
        """Return authentication headers for Dependency-Track API calls."""
        return {
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json",
        }


# Module-level singleton
deptrack_service = DepTrackService()
