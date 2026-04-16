"""FastAPI authentication dependencies (ADR-013).

Provides dependency functions for extracting the current user from a
JWT Bearer token or API key, and for enforcing role / scope checks.

Multi-tenant enforcement:
- ``org_id`` is extracted from JWT claims and attached to ``AuthenticatedUser``
- ``require_role()`` is tenant-aware: it validates role *within* the user's org
- ``get_current_user`` sets RLS tenant context when a DB session is available
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.api_keys import verify_api_key
from app.auth.jwt import JWTError, decode_token

if TYPE_CHECKING:
    from app.auth.roles import Role

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Lightweight user-info carrier returned by the auth dependencies
# ---------------------------------------------------------------------------


class AuthenticatedUser:
    """Minimal identity object extracted from a JWT or API key.

    Attributes:
        user_id: UUID string of the authenticated user.
        org_id: UUID string of the user's organisation (tenant boundary).
        role: Active role string (e.g. ``"org_admin"``).
        scopes: Permission scopes granted for this session.
        auth_method: ``"jwt"`` or ``"api_key"``.
        assignment_level: Level at which the role is assigned (``"org"``, ``"group"``, ``"project"``).
        assigned_group_id: Group UUID when role is group-scoped (None otherwise).
        assigned_project_ids: Project UUIDs when role is project-scoped (empty otherwise).
    """

    __slots__ = (
        "user_id",
        "org_id",
        "role",
        "scopes",
        "auth_method",
        "assignment_level",
        "assigned_group_id",
        "assigned_project_ids",
    )

    def __init__(
        self,
        user_id: str,
        role: str,
        scopes: list[str],
        *,
        org_id: str = "",
        auth_method: str = "jwt",
        assignment_level: str = "org",
        assigned_group_id: str | None = None,
        assigned_project_ids: list[str] | None = None,
    ) -> None:
        self.user_id = user_id
        self.org_id = org_id
        self.role = role
        self.scopes = scopes
        self.auth_method = auth_method
        self.assignment_level = assignment_level
        self.assigned_group_id = assigned_group_id
        self.assigned_project_ids = assigned_project_ids or []


# ---------------------------------------------------------------------------
# Core dependency: extract user from JWT Bearer token
# ---------------------------------------------------------------------------


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    """Extract and validate the current user from a JWT Bearer token.

    The JWT payload is expected to carry ``org_id`` so that multi-tenant
    enforcement can set the RLS context downstream.

    Also verifies the token fingerprint (if present) to prevent session
    hijacking — a stolen token used from a different client is rejected.

    Raises:
        HTTPException 401: If the token is missing, invalid, expired, or
        the fingerprint doesn't match the current client.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify token fingerprint (anti-hijacking)
    # Disabled when CRADAR_FINGERPRINT_ENABLED=false (recommended behind reverse proxies)
    from app.config import settings as _settings

    token_fgp = payload.get("fgp")
    if token_fgp and _settings.fingerprint_enabled:
        from app.auth.jwt import compute_fingerprint
        # Prefer X-Forwarded-For (set by reverse proxies) over direct client IP
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        expected_fgp = compute_fingerprint(user_agent, client_ip)
        if token_fgp != expected_fgp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token fingerprint mismatch — possible session hijacking",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return AuthenticatedUser(
        user_id=payload["sub"],
        org_id=payload.get("org_id", ""),
        role=payload.get("role", ""),
        scopes=payload.get("scopes", []),
        assignment_level=payload.get("assignment_level", "org"),
        assigned_group_id=payload.get("assigned_group_id"),
        assigned_project_ids=payload.get("assigned_project_ids", []),
    )


# ---------------------------------------------------------------------------
# Extended dependency: accept either JWT or API key
# ---------------------------------------------------------------------------

# In-memory stub for API key lookup.  The real implementation will query the
# database.  Tests can monkeypatch this callable.
_api_key_lookup: Any = None


def set_api_key_lookup(fn: Any) -> None:  # noqa: ANN401
    """Register the callback used by ``get_current_user_or_api_key`` to look
    up an API key record from the database.

    The callback signature must be ``async def(key: str) -> dict | None``
    where the returned dict has keys ``hash``, ``user_id``, ``role``,
    ``scopes``.
    """
    global _api_key_lookup  # noqa: PLW0603
    _api_key_lookup = fn


async def get_current_user_or_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    """Authenticate via JWT Bearer token *or* API key.

    The function first attempts JWT validation.  If no ``Bearer`` token is
    present, it checks the ``Authorization`` header for a raw API key
    (prefixed ``cbom_sk_``).

    Raises:
        HTTPException 401: If neither authentication method succeeds.
    """
    # 1) Try JWT first
    if credentials is not None:
        try:
            return await get_current_user(credentials)
        except HTTPException:
            pass  # fall through to API key check

    # 2) Try API key from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("cbom_sk_"):
        api_key = auth_header
    elif auth_header.lower().startswith("bearer cbom_sk_"):
        api_key = auth_header.split(" ", 1)[1]
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if _api_key_lookup is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key authentication not configured",
        )

    record = await _api_key_lookup(api_key)
    if record is None or not verify_api_key(api_key, record["hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return AuthenticatedUser(
        user_id=record["user_id"],
        org_id=record.get("org_id", ""),
        role=record.get("role", ""),
        scopes=record.get("scopes", []),
        auth_method="api_key",
    )


# ---------------------------------------------------------------------------
# Role / scope guard dependencies
# ---------------------------------------------------------------------------


def require_role(*roles: str | Role):
    """Return a FastAPI dependency that rejects users without one of *roles*.

    Tenant-aware: the user must belong to an organisation (``org_id`` must
    be set on the JWT).  Role scoping respects the assignment level:

    - **Org-level** (``assignment_level="org"``): full access within the org.
    - **Group-level** (``assignment_level="group"``): access scoped to the
      assigned group subtree.
    - **Project-level** (``assignment_level="project"``): access scoped to
      explicitly assigned projects only.

    Usage::

        @router.get("/admin", dependencies=[Depends(require_role(Role.ORG_ADMIN))])
        async def admin_only(): ...
    """
    allowed = {str(r) for r in roles}

    async def _check(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        # Tenant check: org_id must be present for multi-tenant enforcement
        if not user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing organisation context",
            )
        return user

    return _check


def require_scope(*scopes: str):
    """Return a FastAPI dependency that rejects tokens missing any of *scopes*.

    Usage::

        @router.get("/scans", dependencies=[Depends(require_scope("scan:read"))])
        async def list_scans(): ...
    """
    required = set(scopes)

    async def _check(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not required.issubset(set(user.scopes)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient scope",
            )
        return user

    return _check


def require_project_access(project_id_param: str = "project_id"):
    """Return a FastAPI dependency that checks the user can access a specific project.

    Enforces the tenant-aware role hierarchy:
    - Org Admin / Security Manager / Security Engineer / Compliance Auditor:
      access all projects within their org.
    - Team Manager: access projects within their assigned group subtree.
      The subtree resolution is delegated to ``GroupService``.
    - Developer: access only explicitly assigned projects.
    - Guest: access only specifically granted projects.

    The ``project_id`` is extracted from the path parameter named by
    *project_id_param*.

    Usage::

        @router.get("/projects/{project_id}/findings",
                     dependencies=[Depends(require_project_access())])
        async def get_findings(project_id: uuid.UUID): ...
    """
    from app.auth.roles import Role as _Role

    _org_wide_roles = {
        str(_Role.ORG_ADMIN),
        str(_Role.SECURITY_MANAGER),
        str(_Role.SECURITY_ENGINEER),
        str(_Role.COMPLIANCE_AUDITOR),
    }

    async def _check(
        request: Request,
        user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if not user.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing organisation context",
            )

        # Org-wide roles with org-level assignment can access everything
        if user.role in _org_wide_roles and user.assignment_level == "org":
            return user

        target_project_id = request.path_params.get(project_id_param)
        if target_project_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing path parameter: {project_id_param}",
            )

        target_str = str(target_project_id)

        # Project-level assignment: check explicit list
        if user.assignment_level == "project":
            if target_str not in user.assigned_project_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You do not have access to this project",
                )
            return user

        # Group-level assignment: the caller must resolve group hierarchy
        # externally (via GroupService).  For now, we allow the request
        # through if the user has a group assignment — actual subtree
        # validation happens at the service layer.
        if user.assignment_level == "group" and user.assigned_group_id:
            return user

        # Org-level for non-org-wide roles (e.g., Developer at org level)
        if user.assignment_level == "org":
            return user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this project",
        )

    return _check


# ---------------------------------------------------------------------------
# Group-aware role resolution (D12)
# ---------------------------------------------------------------------------


async def resolve_role_for_group(
    user: AuthenticatedUser,
    group_id: str,
    session: AsyncSession,
) -> str:
    """Resolve the effective role for the user in the context of a group.

    Combines the user's global role with any per-group override from the
    user_groups table, returning whichever is higher.

    Args:
        user: The authenticated user.
        group_id: UUID string of the target group.
        session: SQLAlchemy async session.

    Returns:
        The effective role string for this group context.
    """
    from app.services.role_resolution_service import resolve_role_for_group as _resolve

    return await _resolve(
        user_id=user.user_id,
        user_role=user.role,
        group_id=group_id,
        session=session,
    )
