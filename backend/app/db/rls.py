"""PostgreSQL Row Level Security (RLS) tenant context helpers.

Sets the ``app.current_org_id`` session variable that RLS policies
reference.  This must be called at the start of every request that
accesses tenant-scoped data.

See migration 003_rls_policies for the matching ``USING`` clauses.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_tenant_context(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Set the current tenant context for RLS policies.

    Uses ``SET LOCAL`` so the setting is scoped to the current transaction
    and automatically cleared on commit/rollback.

    Args:
        session: The active async database session.
        org_id: Organisation UUID to scope all subsequent queries to.
    """
    await session.execute(text("SET LOCAL app.current_org_id = :org_id"), {"org_id": str(org_id)})


async def clear_tenant_context(session: AsyncSession) -> None:
    """Reset the tenant context variable.

    Normally not needed because ``SET LOCAL`` is transaction-scoped,
    but available for explicit cleanup in tests.
    """
    await session.execute(text("RESET app.current_org_id"))
