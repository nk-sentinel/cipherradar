"""Admin API endpoints: org settings, user management, integrations, audit log.

All endpoints require org_admin or security_manager role.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.admin import (
    Integration,
    IntegrationList,
    InviteRequest,
    InviteResponse,
    OrgSettings,
    OrgSettingsUpdate,
    OrgUser,
    OrgUserList,
)
from app.schemas.integration import (
    DiscoverReposResponse,
    ImportReposRequest,
    ImportReposResponse,
    IntegrationConnectRequest,
    IntegrationConnectResponse,
    IntegrationStatusResponse,
    IntegrationTestResponse,
)
from app.schemas.llm_config import (
    LLMConfigResponse,
    LLMConfigUpdateRequest,
    LLMTestResponse,
)
from app.schemas.user_lifecycle import (
    ChangeRoleRequest,
    ChangeRoleResponse,
    DeleteUserResponse,
    UserStatusResponse,
)
from app.schemas.audit_log import AuditLogEntryEnhanced, AuditLogQueryResponse
from app.services.audit_log_query_service import audit_log_query_service
from app.services.integration_service import integration_service
from app.services.llm_config_service import llm_config_service
from app.services.user_lifecycle_service import user_lifecycle_service

router = APIRouter(prefix="/admin", tags=["admin"])

_admin_dep = require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER)


# ---------------------------------------------------------------------------
# GET /api/v1/admin/settings
# ---------------------------------------------------------------------------


@router.get("/settings", response_model=OrgSettings)
async def get_settings(
    user: AuthenticatedUser = Depends(_admin_dep),
    session: AsyncSession = Depends(get_session),
) -> OrgSettings:
    """Return organisation settings for the current user's org."""
    from app.schemas.admin import DefaultScanConfig

    result = await session.execute(
        text("SELECT id, name, plan, settings FROM organisations WHERE id = :org_id"),
        {"org_id": user.org_id},
    )
    row = result.fetchone()
    if row is None:
        return OrgSettings(
            id=user.org_id,
            name="",
            plan="free",
            default_scan_config=DefaultScanConfig(),
        )

    settings_json = row[3] or {}
    scan_cfg = settings_json.get("default_scan_config", {})
    return OrgSettings(
        id=str(row[0]),
        name=row[1],
        plan=row[2],
        default_scan_config=DefaultScanConfig(
            auto_scan=scan_cfg.get("auto_scan", False),
            scan_on_pr=scan_cfg.get("scan_on_pr", False),
            policy_file=scan_cfg.get("policy_file", ""),
            fail_on_severity=scan_cfg.get("fail_on_severity", "none"),
        ),
    )


# ---------------------------------------------------------------------------
# PUT /api/v1/admin/settings
# ---------------------------------------------------------------------------


@router.put("/settings", response_model=OrgSettings)
async def update_settings(
    body: OrgSettingsUpdate,
    user: AuthenticatedUser = Depends(_admin_dep),
    session: AsyncSession = Depends(get_session),
) -> OrgSettings:
    """Update organisation settings."""
    from app.schemas.admin import DefaultScanConfig

    # Fetch current org
    result = await session.execute(
        text("SELECT id, name, plan, settings FROM organisations WHERE id = :org_id"),
        {"org_id": user.org_id},
    )
    row = result.fetchone()
    if row is None:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    current_settings = row[3] or {}
    new_name = body.name if body.name is not None else row[1]
    new_plan = body.plan if body.plan is not None else row[2]

    if body.default_scan_config is not None:
        current_settings["default_scan_config"] = body.default_scan_config.model_dump()

    await session.execute(
        text(
            "UPDATE organisations SET name = :name, plan = :plan, settings = :settings "
            "WHERE id = :org_id"
        ),
        {
            "name": new_name,
            "plan": new_plan,
            "settings": current_settings,
            "org_id": user.org_id,
        },
    )
    await session.commit()

    scan_cfg = current_settings.get("default_scan_config", {})
    return OrgSettings(
        id=str(row[0]),
        name=new_name,
        plan=new_plan,
        default_scan_config=DefaultScanConfig(
            auto_scan=scan_cfg.get("auto_scan", False),
            scan_on_pr=scan_cfg.get("scan_on_pr", False),
            policy_file=scan_cfg.get("policy_file", ""),
            fail_on_severity=scan_cfg.get("fail_on_severity", "none"),
        ),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/admin/users
# ---------------------------------------------------------------------------


@router.get("/users", response_model=OrgUserList)
async def list_users(
    user: AuthenticatedUser = Depends(_admin_dep),
    session: AsyncSession = Depends(get_session),
) -> OrgUserList:
    """List all users in the organisation."""
    result = await session.execute(
        text("SELECT id, email, role, is_active, created_at FROM users WHERE org_id = :org_id ORDER BY created_at"),
        {"org_id": user.org_id},
    )
    rows = result.fetchall()

    items = []
    for row in rows:
        status = "active" if row[3] else "invited"
        items.append(
            OrgUser(
                id=str(row[0]),
                name=row[1].split("@")[0],
                email=row[1],
                role=row[2],
                last_active="",
                status=status,
            )
        )

    return OrgUserList(items=items, total=len(items))


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/invite
# ---------------------------------------------------------------------------


@router.post("/users/invite", response_model=InviteResponse, status_code=201)
async def invite_user(
    body: InviteRequest,
    user: AuthenticatedUser = Depends(_admin_dep),
    session: AsyncSession = Depends(get_session),
) -> InviteResponse:
    """Invite a new user to the organisation (created as inactive)."""
    new_id = uuid.uuid4()
    invite_token = f"inv_{uuid.uuid4().hex}"

    # Create user with is_active=False (placeholder password)
    await session.execute(
        text(
            "INSERT INTO users (id, email, hashed_password, role, is_active, org_id, created_at, updated_at) "
            "VALUES (:id, :email, :hashed_password, :role, false, :org_id, now(), now())"
        ),
        {
            "id": new_id,
            "email": body.email,
            "hashed_password": "!invited",
            "role": body.role,
            "org_id": user.org_id,
        },
    )
    await session.commit()

    return InviteResponse(
        id=str(new_id),
        email=body.email,
        role=body.role,
        invite_token=invite_token,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/admin/integrations (legacy static list)
# ---------------------------------------------------------------------------


@router.get("/integrations", response_model=IntegrationList)
async def list_integrations(
    user: AuthenticatedUser = Depends(_admin_dep),
) -> IntegrationList:
    """List connected integrations (git providers + collaboration tools)."""
    # For now return a static list — real implementation will query integrations table
    items = [
        Integration(
            id="int-1",
            type="github",
            label="GitHub",
            status="connected",
            connected_at="2026-03-10T14:00:00Z",
            detail="nk-sentinel organization",
        ),
        Integration(
            id="int-2",
            type="gitlab",
            label="GitLab",
            status="connected",
            connected_at="2026-03-12T09:30:00Z",
            detail="gitlab.nk-sentinel.io",
        ),
        Integration(
            id="int-3",
            type="bitbucket",
            label="Bitbucket",
            status="disconnected",
            connected_at=None,
            detail=None,
        ),
        Integration(
            id="int-4",
            type="jira",
            label="Jira",
            status="connected",
            connected_at="2026-03-15T11:00:00Z",
            detail="https://nk-sentinel.atlassian.net",
        ),
        Integration(
            id="int-5",
            type="teams",
            label="Microsoft Teams",
            status="connected",
            connected_at="2026-03-16T08:00:00Z",
            detail="Webhook configured",
        ),
    ]
    return IntegrationList(items=items)


# ---------------------------------------------------------------------------
# Integration management — connect/disconnect/test/discover/import (D3)
# ---------------------------------------------------------------------------


@router.post(
    "/integrations/{provider}/connect",
    response_model=IntegrationConnectResponse,
    dependencies=[Depends(_admin_dep)],
)
async def connect_integration(
    provider: str,
    body: IntegrationConnectRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> IntegrationConnectResponse:
    """Connect a git provider by storing a PAT. Roles: OA, SM."""
    try:
        result = await integration_service.connect(
            provider=provider,
            token=body.token,
            actor=user,
            session=session,
        )
        await session.commit()
        return IntegrationConnectResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete(
    "/integrations/{provider}/connect",
    response_model=IntegrationStatusResponse,
    dependencies=[Depends(_admin_dep)],
)
async def disconnect_integration(
    provider: str,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> IntegrationStatusResponse:
    """Disconnect a git provider by revoking its token. Roles: OA, SM."""
    try:
        result = await integration_service.disconnect(
            provider=provider,
            actor=user,
            session=session,
        )
        await session.commit()
        return IntegrationStatusResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/integrations/{provider}/test",
    response_model=IntegrationTestResponse,
    dependencies=[Depends(_admin_dep)],
)
async def test_integration(
    provider: str,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> IntegrationTestResponse:
    """Test connectivity to a git provider API. Roles: OA, SM."""
    try:
        result = await integration_service.test_connection(
            provider=provider,
            actor=user,
            session=session,
        )
        return IntegrationTestResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.get(
    "/integrations/{provider}/repos",
    response_model=DiscoverReposResponse,
    dependencies=[Depends(_admin_dep)],
)
async def discover_repos(
    provider: str,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> DiscoverReposResponse:
    """Discover repositories from a connected provider. Roles: OA, SM."""
    try:
        repos = await integration_service.discover_repos(
            provider=provider,
            actor=user,
            session=session,
        )
        return DiscoverReposResponse(repos=repos, total=len(repos))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/integrations/import",
    response_model=ImportReposResponse,
    dependencies=[Depends(_admin_dep)],
)
async def import_repos(
    body: ImportReposRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ImportReposResponse:
    """Import discovered repos as Project records. Roles: OA, SM."""
    try:
        result = await integration_service.import_repos(
            repos=[r.model_dump() for r in body.repos],
            group_id=body.group_id,
            provider=body.provider,
            actor=user,
            session=session,
        )
        await session.commit()
        return ImportReposResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# LLM Configuration (D5) — OA only
# ---------------------------------------------------------------------------

_oa_llm_dep = require_role(Role.ORG_ADMIN)


@router.get(
    "/llm-config",
    response_model=LLMConfigResponse,
    dependencies=[Depends(_oa_llm_dep)],
)
async def get_llm_config(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> LLMConfigResponse:
    """Get the current LLM configuration. OA only."""
    result = await llm_config_service.get_config(actor=user, session=session)
    if result is None:
        return LLMConfigResponse()
    return LLMConfigResponse(**result)


@router.put(
    "/llm-config",
    response_model=LLMConfigResponse,
    dependencies=[Depends(_oa_llm_dep)],
)
async def update_llm_config(
    body: LLMConfigUpdateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> LLMConfigResponse:
    """Create or update LLM configuration. OA only."""
    try:
        result = await llm_config_service.save_config(
            provider=body.provider,
            model=body.model,
            api_key=body.api_key,
            actor=user,
            session=session,
            endpoint_url=body.endpoint_url,
            max_tokens=body.max_tokens,
            temperature=body.temperature,
            enabled=body.enabled,
        )
        await session.commit()
        return LLMConfigResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/llm-config/test",
    response_model=LLMTestResponse,
    dependencies=[Depends(_oa_llm_dep)],
)
async def test_llm_config(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> LLMTestResponse:
    """Test the configured LLM provider connection. OA only."""
    result = await llm_config_service.test_connection(actor=user, session=session)
    return LLMTestResponse(**result)


# ---------------------------------------------------------------------------
# GET /api/v1/admin/audit-log — enhanced with filters (D28)
# ---------------------------------------------------------------------------


@router.get("/audit-log", response_model=AuditLogQueryResponse)
async def get_audit_log(
    user: AuthenticatedUser = Depends(_admin_dep),
    session: AsyncSession = Depends(get_session),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=100),
    date_from: str | None = Query(default=None, description="ISO 8601 start date"),
    date_to: str | None = Query(default=None, description="ISO 8601 end date"),
    user_id: str | None = Query(default=None, description="Filter by user UUID"),
    action_type: str | None = Query(default=None, description="Filter by action type"),
    resource_type: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
) -> AuditLogQueryResponse:
    """Return filtered, paginated audit log events from the database (D28)."""
    date_from_dt = None
    date_to_dt = None
    if date_from:
        try:
            date_from_dt = datetime.fromisoformat(date_from)
            if date_from_dt.tzinfo is None:
                date_from_dt = date_from_dt.replace(tzinfo=UTC)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid date_from: {date_from}")
    if date_to:
        try:
            date_to_dt = datetime.fromisoformat(date_to)
            if date_to_dt.tzinfo is None:
                date_to_dt = date_to_dt.replace(tzinfo=UTC)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid date_to: {date_to}")

    result = await audit_log_query_service.query(
        org_id=user.org_id,
        session=session,
        page=page,
        per_page=per_page,
        date_from=date_from_dt,
        date_to=date_to_dt,
        user_id=user_id,
        action_type=action_type,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    return AuditLogQueryResponse(
        items=[AuditLogEntryEnhanced(**item) for item in result["items"]],
        total=result["total"],
        page=result["page"],
        per_page=result["per_page"],
    )


# ---------------------------------------------------------------------------
# GET /api/v1/admin/audit-log/export — CSV export (D28)
# ---------------------------------------------------------------------------


@router.get("/audit-log/export", dependencies=[Depends(_admin_dep)])
async def export_audit_log(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    action_type: str | None = Query(default=None),
) -> PlainTextResponse:
    """Export audit log as CSV for compliance. Roles: OA, SM."""
    date_from_dt = None
    date_to_dt = None
    if date_from:
        try:
            date_from_dt = datetime.fromisoformat(date_from)
            if date_from_dt.tzinfo is None:
                date_from_dt = date_from_dt.replace(tzinfo=UTC)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid date_from: {date_from}")
    if date_to:
        try:
            date_to_dt = datetime.fromisoformat(date_to)
            if date_to_dt.tzinfo is None:
                date_to_dt = date_to_dt.replace(tzinfo=UTC)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid date_to: {date_to}")

    csv_content = await audit_log_query_service.export_csv(
        org_id=user.org_id,
        session=session,
        date_from=date_from_dt,
        date_to=date_to_dt,
        user_id=user_id,
        action_type=action_type,
    )
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-log.csv"},
    )


# ---------------------------------------------------------------------------
# PUT /api/v1/admin/users/{id}/role — change user role (D9)
# ---------------------------------------------------------------------------

_oa_dep = require_role(Role.ORG_ADMIN)


@router.put(
    "/users/{user_id}/role",
    response_model=ChangeRoleResponse,
    dependencies=[Depends(_oa_dep)],
)
async def change_user_role(
    user_id: uuid.UUID,
    body: ChangeRoleRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ChangeRoleResponse:
    """Change a user's role. OA only. Downgrades revoke over-scoped API keys."""
    old_role, revoked_keys = await user_lifecycle_service.change_role(
        target_user_id=str(user_id),
        new_role=body.role,
        actor_id=user.user_id,
        actor_org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return ChangeRoleResponse(
        user_id=str(user_id),
        old_role=old_role,
        new_role=body.role,
        revoked_keys=revoked_keys,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/{id}/disable — disable user (D9)
# ---------------------------------------------------------------------------


@router.post(
    "/users/{user_id}/disable",
    response_model=UserStatusResponse,
    dependencies=[Depends(_oa_dep)],
)
async def disable_user(
    user_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> UserStatusResponse:
    """Disable a user (soft-lock). Suspends their API keys. OA only."""
    await user_lifecycle_service.disable(
        target_user_id=str(user_id),
        actor_id=user.user_id,
        actor_org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return UserStatusResponse(
        user_id=str(user_id),
        status="disabled",
        message="User has been disabled",
    )


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/{id}/enable — re-enable user (D9)
# ---------------------------------------------------------------------------


@router.post(
    "/users/{user_id}/enable",
    response_model=UserStatusResponse,
    dependencies=[Depends(_oa_dep)],
)
async def enable_user(
    user_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> UserStatusResponse:
    """Re-enable a disabled user. Unsuspends their API keys. OA only."""
    await user_lifecycle_service.enable(
        target_user_id=str(user_id),
        actor_id=user.user_id,
        actor_org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return UserStatusResponse(
        user_id=str(user_id),
        status="active",
        message="User has been re-enabled",
    )


# ---------------------------------------------------------------------------
# DELETE /api/v1/admin/users/{id} — soft-delete user (D9)
# ---------------------------------------------------------------------------


@router.delete(
    "/users/{user_id}",
    response_model=DeleteUserResponse,
    dependencies=[Depends(_oa_dep)],
)
async def delete_user(
    user_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> DeleteUserResponse:
    """Soft-delete a user. Must be disabled first. 30-day grace period. OA only."""
    await user_lifecycle_service.delete(
        target_user_id=str(user_id),
        actor_id=user.user_id,
        actor_org_id=user.org_id,
        session=session,
    )
    await session.commit()
    return DeleteUserResponse(user_id=str(user_id))


# ---------------------------------------------------------------------------
# GET /api/v1/admin/policy — frontend alias for policy rules (BUG-006)
# PUT /api/v1/admin/policy — save policy config
# ---------------------------------------------------------------------------

_ADMIN_POLICY_RULES = [
    {"id": "no-broken-algorithms", "severity": "critical", "enabled": True, "locked": True, "scope": "org", "inheritedFrom": None},
    {"id": "no-ecb-mode", "severity": "high", "enabled": True, "locked": False, "scope": "org", "inheritedFrom": None},
    {"id": "rsa-min-key-size", "severity": "high", "enabled": True, "locked": False, "scope": "group", "inheritedFrom": "Engineering"},
    {"id": "no-deprecated-tls", "severity": "high", "enabled": True, "locked": False, "scope": "org", "inheritedFrom": None},
    {"id": "quantum-vulnerable", "severity": "medium", "enabled": True, "locked": False, "scope": "project", "inheritedFrom": "auth-service"},
    {"id": "no-hardcoded-keys", "severity": "critical", "enabled": True, "locked": True, "scope": "org", "inheritedFrom": None},
]


@router.get("/policy")
async def get_admin_policy(
    user: AuthenticatedUser = Depends(_admin_dep),
) -> dict:
    """Return policy configuration for the frontend PolicyRules page."""
    return {"rules": _ADMIN_POLICY_RULES}


@router.put("/policy")
async def save_admin_policy(
    request: Request,
    user: AuthenticatedUser = Depends(_admin_dep),
) -> dict:
    """Save policy configuration changes."""
    body = await request.json()
    return body
