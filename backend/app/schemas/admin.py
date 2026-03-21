"""Schemas for admin endpoints: org settings, user management, integrations, audit log."""

from app.schemas.base import CamelCaseModel

# ---------- Org settings ----------


class DefaultScanConfig(CamelCaseModel):
    """Default scan configuration for the organisation."""

    auto_scan: bool = False
    scan_on_pr: bool = False
    policy_file: str = ""
    fail_on_severity: str = "none"


class OrgSettings(CamelCaseModel):
    """Organisation settings response."""

    id: str
    name: str
    plan: str
    default_scan_config: DefaultScanConfig


class OrgSettingsUpdate(CamelCaseModel):
    """Request body for updating organisation settings."""

    name: str | None = None
    plan: str | None = None
    default_scan_config: DefaultScanConfig | None = None


# ---------- User management ----------


class OrgUser(CamelCaseModel):
    """A user within the organisation."""

    id: str
    name: str
    email: str
    role: str
    last_active: str
    status: str


class OrgUserList(CamelCaseModel):
    """Response for listing organisation users."""

    items: list[OrgUser]
    total: int


class InviteRequest(CamelCaseModel):
    """Request body for inviting a new user."""

    email: str
    role: str = "developer"
    name: str = ""


class InviteResponse(CamelCaseModel):
    """Response after inviting a user."""

    id: str
    email: str
    role: str
    invite_token: str
    status: str = "invited"


# ---------- Integrations ----------


class Integration(CamelCaseModel):
    """A connected (or disconnected) integration."""

    id: str
    type: str
    label: str
    status: str
    connected_at: str | None = None
    detail: str | None = None


class IntegrationList(CamelCaseModel):
    """Response for listing integrations."""

    items: list[Integration]


# ---------- Audit log ----------


class AuditLogEntry(CamelCaseModel):
    """A single audit log event."""

    id: str
    timestamp: str
    user: str
    action: str
    resource: str
    detail: str | None = None


class AuditLogResponse(CamelCaseModel):
    """Paginated audit log response."""

    items: list[AuditLogEntry]
    total: int
