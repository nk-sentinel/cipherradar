"""Group hierarchy service for RBAC enforcement.

Resolves which projects a user can access based on their role assignment
level (org / group / project).  Group hierarchy traversal uses a recursive
CTE via the Graph Abstraction Layer pattern (ADR-012, ADR-004).

Role scoping rules (from docs/09-rbac.md):
- Org Admin / Security Manager / Security Engineer / Compliance Auditor:
  all projects within the org (when assigned at org level).
- Team Manager: projects within the assigned group subtree.
- Developer: only explicitly assigned projects.
- Guest: only specifically granted projects.
"""

import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser
from app.models.project import Project


async def get_group_subtree_ids(
    session: AsyncSession,
    root_group_id: uuid.UUID,
) -> list[uuid.UUID]:
    """Return all group IDs in the subtree rooted at *root_group_id*.

    Uses a recursive CTE to walk the ``groups`` table hierarchy.
    The result includes *root_group_id* itself.

    Args:
        session: Active async database session.
        root_group_id: The top-level group to start traversal from.

    Returns:
        List of group UUIDs (root + all descendants at every depth).
    """
    cte_query = text("""
        WITH RECURSIVE group_tree AS (
            SELECT id FROM groups WHERE id = :root_id
            UNION ALL
            SELECT g.id FROM groups g
            INNER JOIN group_tree gt ON g.parent_group_id = gt.id
        )
        SELECT id FROM group_tree
    """)

    result = await session.execute(cte_query, {"root_id": root_group_id})
    return [row[0] for row in result.fetchall()]


async def get_project_ids_in_groups(
    session: AsyncSession,
    group_ids: list[uuid.UUID],
) -> list[uuid.UUID]:
    """Return all project IDs belonging to the given groups.

    Args:
        session: Active async database session.
        group_ids: List of group UUIDs to query.

    Returns:
        List of project UUIDs within those groups.
    """
    if not group_ids:
        return []

    stmt = select(Project.id).where(Project.group_id.in_(group_ids))
    result = await session.execute(stmt)
    return [row[0] for row in result.fetchall()]


async def get_accessible_project_ids(
    session: AsyncSession,
    user: AuthenticatedUser,
) -> list[uuid.UUID]:
    """Resolve which projects a user can access based on their role assignment.

    Applies the hierarchical scoping rules from docs/09-rbac.md:

    1. **Org-level assignment** with an org-wide role: all projects in the org.
    2. **Org-level assignment** with a non-org-wide role (e.g., Developer):
       all projects in the org (developer can see their own; enforced elsewhere).
    3. **Group-level assignment**: all projects in the assigned group subtree
       (recursive CTE traversal).
    4. **Project-level assignment**: only the explicitly listed project IDs.

    Args:
        session: Active async database session.
        user: The authenticated user with role assignment metadata.

    Returns:
        List of project UUIDs the user may access.
    """
    if user.org_uuid is None:
        return []

    org_uuid = user.org_uuid

    # Org-level assignment: return all projects in the org
    if user.assignment_level == "org":
        stmt = select(Project.id).where(Project.org_id == org_uuid)
        result = await session.execute(stmt)
        return [row[0] for row in result.fetchall()]

    # Group-level assignment: resolve group subtree, then projects
    if user.assignment_level == "group" and user.assigned_group_id:
        group_uuid = uuid.UUID(user.assigned_group_id)
        subtree_ids = await get_group_subtree_ids(session, group_uuid)
        return await get_project_ids_in_groups(session, subtree_ids)

    # Project-level assignment: return only explicitly assigned projects
    if user.assignment_level == "project" and user.assigned_project_ids:
        return [uuid.UUID(pid) for pid in user.assigned_project_ids]

    return []


async def can_access_project(
    session: AsyncSession,
    user: AuthenticatedUser,
    project_id: uuid.UUID,
) -> bool:
    """Check whether a user can access a specific project.

    This is a convenience wrapper around ``get_accessible_project_ids``
    for single-project checks.

    Args:
        session: Active async database session.
        user: The authenticated user.
        project_id: The project to check access for.

    Returns:
        True if the user has access to the project.
    """
    accessible = await get_accessible_project_ids(session, user)
    return project_id in accessible
