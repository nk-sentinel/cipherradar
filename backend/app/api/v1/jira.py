"""Jira integration API endpoints — OAuth connect, callback, config, and issue creation (D18)."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.jira import (
    JiraConfigResponse,
    JiraConfigUpdate,
    JiraConnectRequest,
    JiraConnectResponse,
    JiraIssueResponse,
    JiraStatusResponse,
)
from app.services.jira_config_service import jira_config_service
from app.services.jira_service import jira_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["jira"])

_jira_config_roles = require_role(
    Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER, Role.TEAM_MANAGER,
)


# ---------------------------------------------------------------------------
# POST /api/v1/integrations/jira/connect
# ---------------------------------------------------------------------------


@router.post("/integrations/jira/connect", response_model=JiraConnectResponse)
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


@router.get("/integrations/jira/callback", response_model=JiraConnectResponse)
async def jira_callback(
    code: str = Query(description="OAuth authorisation code"),
    state: str = Query(default="", description="OAuth state parameter"),
) -> JiraConnectResponse:
    """Handle the Jira OAuth callback."""
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


@router.get("/integrations/jira/status", response_model=JiraStatusResponse)
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


# ---------------------------------------------------------------------------
# POST /api/v1/findings/{finding_id}/jira — create Jira issue
# ---------------------------------------------------------------------------


@router.post(
    "/findings/{finding_id}/jira",
    response_model=JiraIssueResponse,
    dependencies=[Depends(_jira_config_roles)],
)
async def create_jira_issue(
    finding_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> JiraIssueResponse:
    """Create a Jira issue for a finding. RBAC: OA, SM, SE, TM."""
    result = await jira_config_service.create_issue(
        finding_id=finding_id,
        actor=user,
        session=session,
    )
    return JiraIssueResponse(**result)


# ---------------------------------------------------------------------------
# GET /api/v1/groups/{group_id}/jira-config
# ---------------------------------------------------------------------------


@router.get(
    "/groups/{group_id}/jira-config",
    response_model=JiraConfigResponse,
    dependencies=[Depends(_jira_config_roles)],
)
async def get_group_jira_config(
    group_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> JiraConfigResponse:
    """Get Jira configuration for a group. RBAC: OA, SM, SE, TM."""
    config = await jira_config_service.resolve_config(
        org_id=uuid.UUID(user.org_id),
        session=session,
        group_id=group_id,
    )
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Jira configuration found for this group",
        )
    return JiraConfigResponse(
        id=config.id,
        jira_project_key=config.project_key,
        default_issue_type=config.issue_type,
        priority_mapping=config.priority_mapping,
        custom_fields=config.custom_fields,
        default_assignee=config.default_assignee,
        labels=config.labels,
        scope=config.scope_type,
    )


# ---------------------------------------------------------------------------
# PUT /api/v1/groups/{group_id}/jira-config
# ---------------------------------------------------------------------------


@router.put(
    "/groups/{group_id}/jira-config",
    response_model=JiraConfigResponse,
    dependencies=[Depends(_jira_config_roles)],
)
async def save_group_jira_config(
    group_id: uuid.UUID,
    body: JiraConfigUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> JiraConfigResponse:
    """Save Jira configuration for a group. RBAC: OA, SM, SE, TM."""
    config = await jira_config_service.save_config(
        scope_type="group",
        scope_id=group_id,
        org_id=uuid.UUID(user.org_id),
        config_data=body.model_dump(),
        session=session,
    )
    return JiraConfigResponse(
        id=config.id,
        jira_project_key=config.project_key,
        default_issue_type=config.issue_type,
        priority_mapping=config.priority_mapping,
        custom_fields=config.custom_fields,
        default_assignee=config.default_assignee,
        labels=config.labels,
        scope=config.scope_type,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/projects/{project_id}/jira-config
# ---------------------------------------------------------------------------


@router.get(
    "/projects/{project_id}/jira-config",
    response_model=JiraConfigResponse,
    dependencies=[Depends(_jira_config_roles)],
)
async def get_project_jira_config(
    project_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> JiraConfigResponse:
    """Get Jira configuration for a project (with group fallback)."""
    config = await jira_config_service.resolve_config(
        org_id=uuid.UUID(user.org_id),
        session=session,
        project_id=project_id,
    )
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Jira configuration found for this project or its group",
        )
    return JiraConfigResponse(
        id=config.id,
        jira_project_key=config.project_key,
        default_issue_type=config.issue_type,
        priority_mapping=config.priority_mapping,
        custom_fields=config.custom_fields,
        default_assignee=config.default_assignee,
        labels=config.labels,
        scope=config.scope_type,
    )


# ---------------------------------------------------------------------------
# PUT /api/v1/projects/{project_id}/jira-config
# ---------------------------------------------------------------------------


@router.put(
    "/projects/{project_id}/jira-config",
    response_model=JiraConfigResponse,
    dependencies=[Depends(_jira_config_roles)],
)
async def save_project_jira_config(
    project_id: uuid.UUID,
    body: JiraConfigUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> JiraConfigResponse:
    """Save Jira configuration for a project. RBAC: OA, SM, SE, TM."""
    config = await jira_config_service.save_config(
        scope_type="project",
        scope_id=project_id,
        org_id=uuid.UUID(user.org_id),
        config_data=body.model_dump(),
        session=session,
    )
    return JiraConfigResponse(
        id=config.id,
        jira_project_key=config.project_key,
        default_issue_type=config.issue_type,
        priority_mapping=config.priority_mapping,
        custom_fields=config.custom_fields,
        default_assignee=config.default_assignee,
        labels=config.labels,
        scope=config.scope_type,
    )
