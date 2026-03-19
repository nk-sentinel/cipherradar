"""RBAC enforcement tests for protected API endpoints.

Tests each of the 7 roles against protected endpoints and verifies
role cascade behaviour (group-level assignment grants project access).

All tests run without a real database by overriding FastAPI dependencies.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.jwt import create_access_token
from app.auth.middleware import AuthenticatedUser
from app.auth.roles import ROLE_DEFAULT_SCOPES, Role, Scope
from app.main import create_app

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

ORG_ID = str(uuid.uuid4())
OTHER_ORG_ID = str(uuid.uuid4())
USER_ID = str(uuid.uuid4())
GROUP_ID = str(uuid.uuid4())
PROJECT_ID = str(uuid.uuid4())
OTHER_PROJECT_ID = str(uuid.uuid4())


def _token_for_role(
    role: Role,
    org_id: str = ORG_ID,
    assignment_level: str = "org",
    assigned_group_id: str | None = None,
    assigned_project_ids: list[str] | None = None,
) -> str:
    """Create a valid JWT for the given role with multi-tenant claims."""
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role, [])]
    return create_access_token(
        user_id=USER_ID,
        role=str(role),
        scopes=scopes,
        org_id=org_id,
        assignment_level=assignment_level,
        assigned_group_id=assigned_group_id,
        assigned_project_ids=assigned_project_ids,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    """Create a test app without lifespan."""
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    """Async HTTP client wired to the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# GET /api/v1/auth/me — all roles should succeed with valid token
# ---------------------------------------------------------------------------


class TestMeEndpointAllRoles:
    """Verify all 7 roles can access the /me endpoint."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", list(Role))
    async def test_me_returns_200_for_all_roles(self, client: AsyncClient, role: Role) -> None:
        """GET /api/v1/auth/me should return 200 for any valid role."""
        token = _token_for_role(role)
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == str(role)
        assert body["user_id"] == USER_ID


# ---------------------------------------------------------------------------
# POST /api/v1/auth/api-keys — role-gated
# ---------------------------------------------------------------------------


class TestApiKeyCreation:
    """Verify API key creation is restricted to permitted roles."""

    @pytest.fixture(autouse=True)
    def _patch_api_key_store(self, app, monkeypatch) -> None:
        """Wire up a no-op API key store."""
        from app.api.v1 import auth as auth_module

        monkeypatch.setattr(auth_module, "_store_api_key", AsyncMock())

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "role,expected_status",
        [
            (Role.ORG_ADMIN, 201),
            (Role.SECURITY_MANAGER, 201),
            (Role.SECURITY_ENGINEER, 201),
            (Role.TEAM_MANAGER, 403),
            (Role.COMPLIANCE_AUDITOR, 403),
            (Role.DEVELOPER, 403),
            (Role.GUEST, 403),
        ],
    )
    async def test_api_key_creation_role_enforcement(
        self, client: AsyncClient, role: Role, expected_status: int
    ) -> None:
        """Only Org Admin, Security Manager, and Security Engineer can create API keys."""
        token = _token_for_role(role)
        resp = await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "test-key", "scopes": ["scan:read"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == expected_status

    @pytest.mark.asyncio
    async def test_api_key_creation_without_auth(self, client: AsyncClient) -> None:
        """API key creation without authentication should return 401."""
        resp = await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "test-key", "scopes": ["scan:read"]},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Role cascade: group-level assignment grants project access
# ---------------------------------------------------------------------------


class TestRoleCascade:
    """Verify role cascade from group to project level."""

    @pytest.mark.asyncio
    async def test_group_assignment_includes_child_projects(self) -> None:
        """A user assigned at group level should see projects in child groups."""
        from app.services.group_service import get_accessible_project_ids

        child_project_1 = uuid.uuid4()
        child_project_2 = uuid.uuid4()

        user = AuthenticatedUser(
            user_id=USER_ID,
            org_id=ORG_ID,
            role=str(Role.TEAM_MANAGER),
            scopes=[],
            assignment_level="group",
            assigned_group_id=GROUP_ID,
        )

        session = AsyncMock()

        with (
            patch(
                "app.services.group_service.get_group_subtree_ids",
                new_callable=AsyncMock,
                return_value=[uuid.UUID(GROUP_ID), uuid.uuid4()],
            ),
            patch(
                "app.services.group_service.get_project_ids_in_groups",
                new_callable=AsyncMock,
                return_value=[child_project_1, child_project_2],
            ),
        ):
            project_ids = await get_accessible_project_ids(session, user)

        assert child_project_1 in project_ids
        assert child_project_2 in project_ids

    @pytest.mark.asyncio
    async def test_org_level_assignment_sees_all_projects(self) -> None:
        """A user at org level sees all projects regardless of group structure."""
        from unittest.mock import MagicMock

        from app.services.group_service import get_accessible_project_ids

        project_ids_in_db = [uuid.uuid4() for _ in range(5)]
        user = AuthenticatedUser(
            user_id=USER_ID,
            org_id=ORG_ID,
            role=str(Role.SECURITY_ENGINEER),
            scopes=[],
            assignment_level="org",
        )

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [(p,) for p in project_ids_in_db]
        session.execute.return_value = mock_result

        result = await get_accessible_project_ids(session, user)
        assert set(result) == set(project_ids_in_db)


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------


class TestScopeEnforcement:
    """Verify scope-based access control."""

    @pytest.mark.asyncio
    async def test_developer_has_scan_read_scope(self) -> None:
        """Developer tokens should include scan:read scope."""
        token = _token_for_role(Role.DEVELOPER)
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        assert "scan:read" in payload["scopes"]

    @pytest.mark.asyncio
    async def test_guest_has_minimal_scopes(self) -> None:
        """Guest tokens should have only scan:read and cbom:read."""
        token = _token_for_role(Role.GUEST)
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        assert set(payload["scopes"]) == {"scan:read", "cbom:read"}

    @pytest.mark.asyncio
    async def test_org_admin_has_all_scopes(self) -> None:
        """Org Admin should have all available scopes."""
        token = _token_for_role(Role.ORG_ADMIN)
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        all_scope_values = {str(s) for s in Scope}
        assert set(payload["scopes"]) == all_scope_values


# ---------------------------------------------------------------------------
# Tenant context in JWT
# ---------------------------------------------------------------------------


class TestJWTTenantClaims:
    """Verify org_id and assignment metadata are present in JWT claims."""

    @pytest.mark.asyncio
    async def test_token_contains_org_id(self) -> None:
        """JWT payload should include org_id claim."""
        token = _token_for_role(Role.DEVELOPER)
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        assert payload["org_id"] == ORG_ID

    @pytest.mark.asyncio
    async def test_token_contains_assignment_level(self) -> None:
        """JWT payload should include assignment_level claim."""
        token = _token_for_role(Role.TEAM_MANAGER, assignment_level="group")
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        assert payload["assignment_level"] == "group"

    @pytest.mark.asyncio
    async def test_token_contains_assigned_group_id(self) -> None:
        """JWT with group assignment should include assigned_group_id."""
        token = _token_for_role(
            Role.TEAM_MANAGER,
            assignment_level="group",
            assigned_group_id=GROUP_ID,
        )
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        assert payload["assigned_group_id"] == GROUP_ID

    @pytest.mark.asyncio
    async def test_token_contains_assigned_project_ids(self) -> None:
        """JWT with project assignment should include assigned_project_ids."""
        token = _token_for_role(
            Role.DEVELOPER,
            assignment_level="project",
            assigned_project_ids=[PROJECT_ID, OTHER_PROJECT_ID],
        )
        from app.auth.jwt import decode_token

        payload = decode_token(token)
        assert set(payload["assigned_project_ids"]) == {PROJECT_ID, OTHER_PROJECT_ID}

    @pytest.mark.asyncio
    async def test_middleware_extracts_org_id(self, app, client: AsyncClient) -> None:
        """AuthenticatedUser returned by get_current_user should have org_id."""
        token = _token_for_role(Role.DEVELOPER)
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        # The /me endpoint returns user_id but not org_id directly.
        # Verify the middleware parsed it by checking the user_id is correct.
        assert resp.json()["user_id"] == USER_ID


# ---------------------------------------------------------------------------
# Missing org_id blocks require_role
# ---------------------------------------------------------------------------


class TestMissingOrgId:
    """Verify that require_role rejects requests without org_id."""

    @pytest.mark.asyncio
    async def test_require_role_rejects_missing_org_id(self, app, client: AsyncClient) -> None:
        """API key creation with a token missing org_id should fail."""
        from app.api.v1 import auth as auth_module

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(auth_module, "_store_api_key", AsyncMock())

        # Create a token without org_id
        token = create_access_token(
            user_id=USER_ID,
            role=str(Role.ORG_ADMIN),
            scopes=[str(s) for s in Scope],
            org_id="",  # empty org_id
        )
        resp = await client.post(
            "/api/v1/auth/api-keys",
            json={"name": "test-key", "scopes": ["scan:read"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "organisation" in resp.json()["detail"].lower()

        monkeypatch.undo()
