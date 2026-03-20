"""Portfolio API — cross-repo aggregation endpoints for Team Manager dashboard."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.schemas.portfolio import (
    PortfolioCompliance,
    PortfolioQuantum,
    PortfolioSummary,
)
from app.services.group_service import get_accessible_project_ids
from app.services.portfolio_service import (
    get_portfolio_compliance,
    get_portfolio_quantum,
    get_portfolio_summary,
)

router = APIRouter(prefix="/portfolio", tags=["portfolio"])


@router.get("/summary", response_model=PortfolioSummary)
async def portfolio_summary(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> PortfolioSummary:
    """Portfolio summary: all repos, heat map, quantum readiness %, top 10 riskiest.

    Group-scoped: only returns data for repos the user can access.
    """
    project_ids = await get_accessible_project_ids(session, user)
    return await get_portfolio_summary(session, project_ids, user.user_id)


@router.get("/compliance", response_model=PortfolioCompliance)
async def portfolio_compliance(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> PortfolioCompliance:
    """Per-framework compliance scores across all accessible repos (6 frameworks).

    Group-scoped: only evaluates repos the user can access.
    """
    project_ids = await get_accessible_project_ids(session, user)
    return await get_portfolio_compliance(session, project_ids, user.user_id)


@router.get("/quantum", response_model=PortfolioQuantum)
async def portfolio_quantum(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> PortfolioQuantum:
    """Aggregate quantum readiness: vulnerable/safe/broken/unknown counts + migration priority.

    Group-scoped: only evaluates repos the user can access.
    """
    project_ids = await get_accessible_project_ids(session, user)
    return await get_portfolio_quantum(session, project_ids, user.user_id)
