"""Jira integration API endpoints — OAuth connect, callback, and status."""

import logging

from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.jira import (
    JiraConnectRequest,
    JiraConnectResponse,
    JiraStatusResponse,
)
from app.services.jira_service import jira_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/jira", tags=["jira"])


# ---------------------------------------------------------------------------
# POST /api/v1/integrations/jira/connect
# ---------------------------------------------------------------------------


@router.post("/connect", response_model=JiraConnectResponse)
async def jira_connect(
    body: JiraConnectRequest,
    org_id: str = Query(description="Organisation ID"),
) -> JiraConnectResponse:
    """Initiate Jira OAuth connection by exchanging an authorisation code."""
    try:
        result = await jira_service.connect(org_id, body.code)
        return JiraConnectResponse(
            connected=result.get("connected", False),
            site_name=result.get("site_name", ""),
            cloud_id=result.get("cloud_id", ""),
        )
    except Exception as exc:
        logger.warning("Jira connect failed for org %s", org_id, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to Jira",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/integrations/jira/callback
# ---------------------------------------------------------------------------


@router.get("/callback", response_model=JiraConnectResponse)
async def jira_callback(
    code: str = Query(description="OAuth authorisation code"),
    state: str = Query(default="", description="OAuth state parameter"),
) -> JiraConnectResponse:
    """Handle the Jira OAuth callback."""
    # In production, ``state`` would carry the org_id or session reference.
    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing state parameter (org_id)",
        )

    try:
        result = await jira_service.connect(state, code)
        return JiraConnectResponse(
            connected=result.get("connected", False),
            site_name=result.get("site_name", ""),
            cloud_id=result.get("cloud_id", ""),
        )
    except Exception as exc:
        logger.warning("Jira callback failed for org %s", state, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to complete Jira OAuth",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/integrations/jira/status
# ---------------------------------------------------------------------------


@router.get("/status", response_model=JiraStatusResponse)
async def jira_status(
    org_id: str = Query(description="Organisation ID"),
) -> JiraStatusResponse:
    """Get Jira integration connection status."""
    result = await jira_service.get_status(org_id)
    return JiraStatusResponse(
        connected=result.get("connected", False),
        site_name=result.get("site_name", ""),
        cloud_id=result.get("cloud_id", ""),
    )
