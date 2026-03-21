"""Admin API endpoints: org settings, user management, integrations, audit log.

All endpoints require org_admin or security_manager role.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.admin import (
    AuditLogEntry,
    AuditLogResponse,
    Integration,
    IntegrationList,
    InviteRequest,
    InviteResponse,
    OrgSettings,
    OrgSettingsUpdate,
    OrgUser,
    OrgUserList,
)

router = APIRouter(prefix="/admin", tags=["admin"])

_admin_dep = require_role(Role.ORG_ADMIN, Role.SECURITY_MANAGER)


# ---------------------------------------------------------------------------
# Hardcoded mock audit events (no audit_events table yet)
# ---------------------------------------------------------------------------

_MOCK_AUDIT_LOG: list[dict[str, str | None]] = [
    {
        "id": "al-001",
        "timestamp": "2026-03-21T10:05:00Z",
        "user": "alex.chen@nk-sentinel.io",
        "action": "scan.completed",
        "resource": "payment-service",
        "detail": "Scan #45 completed with 3 critical findings",
    },
    {
        "id": "al-002",
        "timestamp": "2026-03-21T09:58:00Z",
        "user": "alex.chen@nk-sentinel.io",
        "action": "scan.started",
        "resource": "payment-service",
        "detail": "Scan #45 triggered manually",
    },
    {
        "id": "al-003",
        "timestamp": "2026-03-21T09:30:00Z",
        "user": "sarah.kim@nk-sentinel.io",
        "action": "policy.updated",
        "resource": "Default Policy",
        "detail": "Updated fail-on severity from medium to high",
    },
    {
        "id": "al-004",
        "timestamp": "2026-03-21T08:45:00Z",
        "user": "sarah.kim@nk-sentinel.io",
        "action": "finding.suppressed",
        "resource": "auth-api / SHA-1 usage",
        "detail": "Suppressed with justification: legacy compatibility",
    },
    {
        "id": "al-005",
        "timestamp": "2026-03-21T08:00:00Z",
        "user": "alex.chen@nk-sentinel.io",
        "action": "user.invite",
        "resource": "tom.nguyen@nk-sentinel.io",
        "detail": "Invited as Guest / Viewer",
    },
    {
        "id": "al-006",
        "timestamp": "2026-03-20T17:30:00Z",
        "user": "james.liu@nk-sentinel.io",
        "action": "cbom.exported",
        "resource": "data-pipeline",
        "detail": "Exported CycloneDX 1.7 JSON",
    },
    {
        "id": "al-007",
        "timestamp": "2026-03-20T16:00:00Z",
        "user": "alex.chen@nk-sentinel.io",
        "action": "user.role_change",
        "resource": "david.park@nk-sentinel.io",
        "detail": "Changed role from Developer to Compliance Auditor",
    },
    {
        "id": "al-008",
        "timestamp": "2026-03-20T14:15:00Z",
        "user": "alex.chen@nk-sentinel.io",
        "action": "settings.updated",
        "resource": "Org Settings",
        "detail": "Enabled auto-scan on PR merge",
    },
    {
        "id": "al-009",
        "timestamp": "2026-03-20T12:00:00Z",
        "user": "sarah.kim@nk-sentinel.io",
        "action": "integration.connected",
        "resource": "Microsoft Teams",
        "detail": "Webhook configured for #cipherradar-alerts",
    },
    {
        "id": "al-010",
        "timestamp": "2026-03-20T10:00:00Z",
        "user": "alex.chen@nk-sentinel.io",
        "action": "user.login",
        "resource": "Session",
        "detail": None,
    },
]


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
# GET /api/v1/admin/integrations
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
# GET /api/v1/admin/audit-log
# ---------------------------------------------------------------------------


@router.get("/audit-log", response_model=AuditLogResponse)
async def get_audit_log(
    user: AuthenticatedUser = Depends(_admin_dep),
) -> AuditLogResponse:
    """Return audit log events (mock data — no audit_events table yet)."""
    items = [
        AuditLogEntry(
            id=entry["id"],
            timestamp=entry["timestamp"],
            user=entry["user"],
            action=entry["action"],
            resource=entry["resource"],
            detail=entry.get("detail"),
        )
        for entry in _MOCK_AUDIT_LOG
    ]
    return AuditLogResponse(items=items, total=len(items))
