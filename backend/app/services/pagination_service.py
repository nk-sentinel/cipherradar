"""Reusable pagination utility for SQLAlchemy async queries.

Usage::

    from app.services.pagination_service import paginate

    stmt = select(Finding).where(Finding.org_id == org_id)
    result = await paginate(query=stmt, page=page, per_page=per_page, session=session)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from app.schemas.pagination import PaginatedResponse

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import Select


async def paginate(
    query: Any,
    page: int,
    per_page: int,
    session: AsyncSession,
) -> PaginatedResponse:
    """Execute a paginated query and return a ``PaginatedResponse``.

    Parameters
    ----------
    query:
        A SQLAlchemy ``select()`` statement.  The function will derive a
        count query automatically and apply ``offset`` / ``limit``.
    page:
        1-based page number.
    per_page:
        Number of items per page.
    session:
        An ``AsyncSession`` used to execute both the count and data queries.

    Returns
    -------
    PaginatedResponse
        Contains ``items``, ``total``, ``page``, and ``per_page``.
    """
    # --- total count ---
    count_query = query.with_only_columns(func.count()).order_by(None)
    count_result = await session.execute(count_query)
    total: int = count_result.scalar_one()

    # --- fetch page ---
    offset = (page - 1) * per_page
    paginated_query = query.offset(offset).limit(per_page)
    data_result = await session.execute(paginated_query)
    items = list(data_result.scalars().all())

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )
