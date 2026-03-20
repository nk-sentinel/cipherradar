"""Dependency-Track integration API endpoints — connect, status, and sync."""

import logging

from fastapi import APIRouter, HTTPException, status

from app.schemas.deptrack import (
    DepTrackConnectRequest,
    DepTrackConnectResponse,
    DepTrackStatusResponse,
    DepTrackSyncResponse,
)
from app.services.deptrack_service import deptrack_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/dependency-track", tags=["dependency-track"])


# ---------------------------------------------------------------------------
# POST /api/v1/integrations/dependency-track/connect
# ---------------------------------------------------------------------------


@router.post("/connect", response_model=DepTrackConnectResponse)
async def deptrack_connect(body: DepTrackConnectRequest) -> DepTrackConnectResponse:
    """Save Dependency-Track URL and API key and verify connectivity."""
    try:
        result = await deptrack_service.connect(body.base_url, body.api_key)
        return DepTrackConnectResponse(
            connected=result["connected"],
            base_url=result.get("base_url", ""),
            message=result.get("message", ""),
        )
    except Exception as exc:
        logger.warning("Dependency-Track connect failed", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to Dependency-Track",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/integrations/dependency-track/status
# ---------------------------------------------------------------------------


@router.get("/status", response_model=DepTrackStatusResponse)
async def deptrack_status() -> DepTrackStatusResponse:
    """Test Dependency-Track connection and return status."""
    result = await deptrack_service.get_status()
    return DepTrackStatusResponse(
        connected=result["connected"],
        base_url=result.get("base_url", ""),
        server_version=result.get("server_version", ""),
        message=result.get("message", ""),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/integrations/dependency-track/sync/{scan_id}
# ---------------------------------------------------------------------------


@router.post("/sync/{scan_id}", response_model=DepTrackSyncResponse)
async def deptrack_sync(scan_id: str, project_uuid: str) -> DepTrackSyncResponse:
    """Manually trigger a CBOM sync to Dependency-Track for a given scan.

    Args:
        scan_id: CipherRadar scan ID.
        project_uuid: Dependency-Track project UUID (query parameter).
    """
    if not deptrack_service.base_url or not deptrack_service.api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dependency-Track integration not configured. Call /connect first.",
        )

    result = await deptrack_service.sync_scan(scan_id, project_uuid)
    return DepTrackSyncResponse(
        synced=result["synced"],
        project_uuid=result.get("project_uuid", ""),
        token=result.get("token", ""),
        message=result.get("message", ""),
    )
