"""Role resolution service (D12).

Provides effective role computation with per-group role overrides.
The effective role is the maximum of the user's global role and their
group-specific role (if any).
"""

from __future__ import annotations

import uuid as _uuid
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models.user_group import UserGroup

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# Role rank from lowest (guest=0) to highest (org_admin=6)
ROLE_RANK: dict[str, int] = {
    "guest": 0,
    "developer": 1,
    "compliance_auditor": 2,
    "team_manager": 3,
    "security_engineer": 4,
    "security_manager": 5,
    "org_admin": 6,
}


def get_effective_role(user_role: str, group_role: str | None) -> str:
    """Return the higher-privilege role between global and group roles.

    The user's global role acts as a floor. If the group role is higher,
    it takes precedence for that group context.

    Args:
        user_role: The user's global role.
        group_role: The user's role in a specific group (may be None).

    Returns:
        The effective role string.
    """
    if group_role is None:
        return user_role

    user_rank = ROLE_RANK.get(user_role, 0)
    group_rank = ROLE_RANK.get(group_role, 0)

    if user_rank >= group_rank:
        return user_role
    return group_role


async def resolve_role_for_group(
    user_id: str,
    user_role: str,
    group_id: str,
    session: AsyncSession,
) -> str:
    """Resolve the effective role for a user within a specific group.

    Queries the user_group table for a per-group role override, then
    returns the maximum of the global role and the group role.

    Args:
        user_id: UUID of the user.
        user_role: The user's global role.
        group_id: UUID of the group.
        session: SQLAlchemy async session.

    Returns:
        The effective role string for this group context.
    """
    result = await session.execute(
        select(UserGroup.role).where(
            UserGroup.user_id == _uuid.UUID(user_id),
            UserGroup.group_id == _uuid.UUID(group_id),
        )
    )
    row = result.scalar_one_or_none()
    group_role = row if isinstance(row, str) else None
    return get_effective_role(user_role, group_role)
