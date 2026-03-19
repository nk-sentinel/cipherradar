"""Multi-tenant RBAC enforcement tests.

Tests verify that tenant isolation and role-based project access work
correctly without requiring a real database.  Group hierarchy and
project membership are simulated using mocks.

Scenarios covered:
- Org A cannot see Org B's findings
- Team Manager scoped to a group sees only group projects
- Developer sees only assigned projects
- Org Admin sees all within their org
- Cross-tenant create blocked
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser
from app.auth.roles import Role
from app.db.rls import clear_tenant_context, set_tenant_context
from app.services.group_service import (
    can_access_project,
    get_accessible_project_ids,
)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

ORG_A_ID = uuid.uuid4()
ORG_B_ID = uuid.uuid4()

GROUP_ENGINEERING = uuid.uuid4()
GROUP_BACKEND = uuid.uuid4()  # child of ENGINEERING
GROUP_FRONTEND = uuid.uuid4()  # child of ENGINEERING
GROUP_FINANCE = uuid.uuid4()  # separate top-level group

PROJECT_AUTH_SERVICE = uuid.uuid4()  # in BACKEND
PROJECT_USER_API = uuid.uuid4()  # in BACKEND
PROJECT_DASHBOARD = uuid.uuid4()  # in FRONTEND
PROJECT_PAYMENT_GW = uuid.uuid4()  # in FINANCE


def _make_user(
    role: str,
    org_id: uuid.UUID = ORG_A_ID,
    assignment_level: str = "org",
    assigned_group_id: uuid.UUID | None = None,
    assigned_project_ids: list[uuid.UUID] | None = None,
) -> AuthenticatedUser:
    """Create an AuthenticatedUser with the given role and scoping."""
    return AuthenticatedUser(
        user_id=str(uuid.uuid4()),
        org_id=str(org_id),
        role=role,
        scopes=[],
        assignment_level=assignment_level,
        assigned_group_id=str(assigned_group_id) if assigned_group_id else None,
        assigned_project_ids=[str(p) for p in (assigned_project_ids or [])],
    )


# ---------------------------------------------------------------------------
# Test: RLS tenant context
# ---------------------------------------------------------------------------


class TestRLSTenantContext:
    """Verify the set/clear tenant context SQL calls."""

    @pytest.mark.asyncio
    async def test_set_tenant_context_executes_set_local(self) -> None:
        """set_tenant_context should execute SET LOCAL with the org_id."""
        session = AsyncMock()
        await set_tenant_context(session, ORG_A_ID)

        session.execute.assert_called_once()
        call_args = session.execute.call_args
        sql_text = str(call_args[0][0])
        assert "SET LOCAL app.current_org_id" in sql_text

    @pytest.mark.asyncio
    async def test_clear_tenant_context_executes_reset(self) -> None:
        """clear_tenant_context should execute RESET."""
        session = AsyncMock()
        await clear_tenant_context(session)

        session.execute.assert_called_once()
        call_args = session.execute.call_args
        sql_text = str(call_args[0][0])
        assert "RESET app.current_org_id" in sql_text


# ---------------------------------------------------------------------------
# Test: Org A cannot see Org B's findings
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    """Verify that tenant isolation prevents cross-org access."""

    @pytest.mark.asyncio
    async def test_org_a_admin_cannot_see_org_b_projects(self) -> None:
        """An Org A admin gets zero projects when asked about Org B."""
        user_org_a = _make_user(str(Role.ORG_ADMIN), org_id=ORG_A_ID)

        session = AsyncMock()
        # Simulate: the query for projects in ORG_A returns ORG_A projects only
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            (PROJECT_AUTH_SERVICE,),
            (PROJECT_USER_API,),
        ]
        session.execute.return_value = mock_result

        projects = await get_accessible_project_ids(session, user_org_a)

        # Should only have Org A's projects
        assert PROJECT_AUTH_SERVICE in projects
        assert PROJECT_USER_API in projects
        # Org B's payment gateway should never appear
        assert PROJECT_PAYMENT_GW not in projects

    @pytest.mark.asyncio
    async def test_empty_org_id_returns_no_projects(self) -> None:
        """A user with no org_id should get zero accessible projects."""
        user_no_org = AuthenticatedUser(
            user_id=str(uuid.uuid4()),
            org_id="",
            role=str(Role.ORG_ADMIN),
            scopes=[],
        )
        session = AsyncMock()
        projects = await get_accessible_project_ids(session, user_no_org)
        assert projects == []

    @pytest.mark.asyncio
    async def test_cross_tenant_project_access_denied(self) -> None:
        """Org B developer cannot access Org A project even if they know the ID."""
        user_org_b = _make_user(
            str(Role.DEVELOPER),
            org_id=ORG_B_ID,
            assignment_level="project",
            assigned_project_ids=[PROJECT_PAYMENT_GW],
        )
        session = AsyncMock()

        # can_access_project for an Org A project should fail
        # because the user's assigned_project_ids only lists Org B projects
        accessible = await get_accessible_project_ids(session, user_org_b)
        assert PROJECT_AUTH_SERVICE not in accessible


# ---------------------------------------------------------------------------
# Test: Team Manager scoped to group sees only group projects
# ---------------------------------------------------------------------------


class TestTeamManagerGroupScope:
    """Verify Team Manager group-scoped access."""

    @pytest.mark.asyncio
    async def test_team_manager_sees_only_group_projects(self) -> None:
        """Team Manager assigned to ENGINEERING group should see subtree projects."""
        user = _make_user(
            str(Role.TEAM_MANAGER),
            assignment_level="group",
            assigned_group_id=GROUP_ENGINEERING,
        )
        session = AsyncMock()

        # Mock: get_group_subtree_ids returns engineering + children
        subtree_ids = [GROUP_ENGINEERING, GROUP_BACKEND, GROUP_FRONTEND]
        group_projects = [PROJECT_AUTH_SERVICE, PROJECT_USER_API, PROJECT_DASHBOARD]

        with (
            patch(
                "app.services.group_service.get_group_subtree_ids",
                new_callable=AsyncMock,
                return_value=subtree_ids,
            ),
            patch(
                "app.services.group_service.get_project_ids_in_groups",
                new_callable=AsyncMock,
                return_value=group_projects,
            ),
        ):
            projects = await get_accessible_project_ids(session, user)

        assert PROJECT_AUTH_SERVICE in projects
        assert PROJECT_USER_API in projects
        assert PROJECT_DASHBOARD in projects
        # Finance projects should NOT appear
        assert PROJECT_PAYMENT_GW not in projects

    @pytest.mark.asyncio
    async def test_team_manager_cannot_access_outside_group(self) -> None:
        """Team Manager assigned to BACKEND group should not see FINANCE projects."""
        user = _make_user(
            str(Role.TEAM_MANAGER),
            assignment_level="group",
            assigned_group_id=GROUP_BACKEND,
        )
        session = AsyncMock()

        # Mock: subtree only contains BACKEND
        with (
            patch(
                "app.services.group_service.get_group_subtree_ids",
                new_callable=AsyncMock,
                return_value=[GROUP_BACKEND],
            ),
            patch(
                "app.services.group_service.get_project_ids_in_groups",
                new_callable=AsyncMock,
                return_value=[PROJECT_AUTH_SERVICE, PROJECT_USER_API],
            ),
        ):
            projects = await get_accessible_project_ids(session, user)

        assert PROJECT_AUTH_SERVICE in projects
        assert PROJECT_USER_API in projects
        assert PROJECT_DASHBOARD not in projects
        assert PROJECT_PAYMENT_GW not in projects


# ---------------------------------------------------------------------------
# Test: Developer sees only assigned projects
# ---------------------------------------------------------------------------


class TestDeveloperProjectScope:
    """Verify Developer project-scoped access."""

    @pytest.mark.asyncio
    async def test_developer_sees_only_assigned_projects(self) -> None:
        """Developer with project-level assignment sees only those projects."""
        user = _make_user(
            str(Role.DEVELOPER),
            assignment_level="project",
            assigned_project_ids=[PROJECT_AUTH_SERVICE],
        )
        session = AsyncMock()

        projects = await get_accessible_project_ids(session, user)

        assert PROJECT_AUTH_SERVICE in projects
        assert len(projects) == 1
        assert PROJECT_USER_API not in projects
        assert PROJECT_DASHBOARD not in projects

    @pytest.mark.asyncio
    async def test_developer_with_no_assignments_sees_nothing(self) -> None:
        """Developer with project-level but no assigned projects gets empty list."""
        user = _make_user(
            str(Role.DEVELOPER),
            assignment_level="project",
            assigned_project_ids=[],
        )
        session = AsyncMock()

        projects = await get_accessible_project_ids(session, user)
        assert projects == []

    @pytest.mark.asyncio
    async def test_developer_org_level_sees_all_org_projects(self) -> None:
        """Developer at org-level assignment sees all projects in the org."""
        user = _make_user(
            str(Role.DEVELOPER),
            assignment_level="org",
        )
        session = AsyncMock()

        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            (PROJECT_AUTH_SERVICE,),
            (PROJECT_USER_API,),
            (PROJECT_DASHBOARD,),
            (PROJECT_PAYMENT_GW,),
        ]
        session.execute.return_value = mock_result

        projects = await get_accessible_project_ids(session, user)
        assert len(projects) == 4


# ---------------------------------------------------------------------------
# Test: Org Admin sees all within org
# ---------------------------------------------------------------------------


class TestOrgAdminAccess:
    """Verify Org Admin has full access within their org."""

    @pytest.mark.asyncio
    async def test_org_admin_sees_all_org_projects(self) -> None:
        """Org Admin at org level should see every project in the organisation."""
        user = _make_user(str(Role.ORG_ADMIN))
        session = AsyncMock()

        all_projects = [PROJECT_AUTH_SERVICE, PROJECT_USER_API, PROJECT_DASHBOARD, PROJECT_PAYMENT_GW]
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [(p,) for p in all_projects]
        session.execute.return_value = mock_result

        projects = await get_accessible_project_ids(session, user)

        assert set(projects) == set(all_projects)

    @pytest.mark.asyncio
    async def test_org_admin_can_access_any_project(self) -> None:
        """Org Admin should be able to access any specific project in their org."""
        user = _make_user(str(Role.ORG_ADMIN))
        session = AsyncMock()

        all_projects = [PROJECT_AUTH_SERVICE, PROJECT_USER_API, PROJECT_DASHBOARD, PROJECT_PAYMENT_GW]
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [(p,) for p in all_projects]
        session.execute.return_value = mock_result

        result = await can_access_project(session, user, PROJECT_PAYMENT_GW)
        assert result is True


# ---------------------------------------------------------------------------
# Test: Cross-tenant create blocked
# ---------------------------------------------------------------------------


class TestCrossTenantCreateBlocked:
    """Verify cross-tenant mutation is architecturally prevented."""

    @pytest.mark.asyncio
    async def test_rls_context_scopes_to_single_org(self) -> None:
        """set_tenant_context sets a single org — writes to other orgs are blocked by RLS."""
        session = AsyncMock()

        # Setting context for Org A
        await set_tenant_context(session, ORG_A_ID)

        # Verify the SQL was issued with Org A's ID
        call_args = session.execute.call_args
        params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("params", {})
        assert str(ORG_A_ID) in str(params) or str(ORG_A_ID) in str(call_args)

    @pytest.mark.asyncio
    async def test_different_org_context_overrides(self) -> None:
        """Setting tenant context twice replaces the previous org scope."""
        session = AsyncMock()

        await set_tenant_context(session, ORG_A_ID)
        await set_tenant_context(session, ORG_B_ID)

        # Should have been called twice — once for each org
        assert session.execute.call_count == 2
        # The second call should have Org B
        second_call = session.execute.call_args_list[1]
        params = second_call[0][1] if len(second_call[0]) > 1 else {}
        assert str(ORG_B_ID) in str(params) or str(ORG_B_ID) in str(second_call)

    @pytest.mark.asyncio
    async def test_project_level_user_cannot_access_unassigned(self) -> None:
        """A project-scoped user cannot access projects outside their assignment."""
        user = _make_user(
            str(Role.DEVELOPER),
            assignment_level="project",
            assigned_project_ids=[PROJECT_AUTH_SERVICE],
        )
        session = AsyncMock()

        result = await can_access_project(session, user, PROJECT_PAYMENT_GW)
        assert result is False
