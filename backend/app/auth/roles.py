"""RBAC role and scope definitions (ADR-006, ADR-013).

Roles mirror the 7-role model from docs/09-rbac.md.
Scopes control fine-grained permission on both JWT tokens and API keys.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """Human user roles."""

    ORG_ADMIN = "org_admin"
    SECURITY_MANAGER = "security_manager"
    SECURITY_ENGINEER = "security_engineer"
    TEAM_MANAGER = "team_manager"
    COMPLIANCE_AUDITOR = "compliance_auditor"
    DEVELOPER = "developer"
    GUEST = "guest"


class Scope(StrEnum):
    """Permission scopes assignable to tokens and API keys."""

    SCAN_READ = "scan:read"
    SCAN_WRITE = "scan:write"
    CBOM_READ = "cbom:read"
    PROJECT_READ = "project:read"
    PROJECT_WRITE = "project:write"
    REPORT_READ = "report:read"


# Scopes that may NEVER be granted to API keys (ADR-013 / OQ-RBAC-7).
POLICY_WRITE_FORBIDDEN_ON_API_KEYS = True

# Default scopes granted to each role when a JWT is issued.
ROLE_DEFAULT_SCOPES: dict[Role, list[Scope]] = {
    Role.ORG_ADMIN: list(Scope),
    Role.SECURITY_MANAGER: list(Scope),
    Role.SECURITY_ENGINEER: [
        Scope.SCAN_READ,
        Scope.SCAN_WRITE,
        Scope.CBOM_READ,
        Scope.PROJECT_READ,
        Scope.PROJECT_WRITE,
        Scope.REPORT_READ,
    ],
    Role.TEAM_MANAGER: [
        Scope.SCAN_READ,
        Scope.SCAN_WRITE,
        Scope.CBOM_READ,
        Scope.PROJECT_READ,
        Scope.REPORT_READ,
    ],
    Role.COMPLIANCE_AUDITOR: [
        Scope.SCAN_READ,
        Scope.CBOM_READ,
        Scope.REPORT_READ,
    ],
    Role.DEVELOPER: [
        Scope.SCAN_READ,
        Scope.SCAN_WRITE,
        Scope.CBOM_READ,
        Scope.PROJECT_READ,
    ],
    Role.GUEST: [
        Scope.SCAN_READ,
        Scope.CBOM_READ,
    ],
}

# Roles allowed to create API keys (per docs/09-rbac.md section 9.1).
API_KEY_CREATOR_ROLES: frozenset[Role] = frozenset(
    {
        Role.ORG_ADMIN,
        Role.SECURITY_MANAGER,
        Role.SECURITY_ENGINEER,
    }
)
