"""Portfolio API — cross-repo aggregation endpoints for Team Manager dashboard."""

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.models.finding import Finding
from app.models.project import Project
from app.schemas.base import CamelCaseModel
from app.schemas.portfolio import (
    HeatMapEntry,
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


# ---------------------------------------------------------------------------
# Heatmap schemas (repo-level, all 5 severity levels)
# ---------------------------------------------------------------------------


class HeatmapResponse(CamelCaseModel):
    """Portfolio heatmap: per-repo severity breakdown."""

    repos: list[HeatMapEntry]


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


@router.get("/heatmap", response_model=HeatmapResponse)
async def portfolio_heatmap(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> HeatmapResponse:
    """Portfolio heatmap: per-repo severity breakdown (all 5 levels).

    Returns repos with critical/high/medium/low/info counts.
    Group-scoped to the authenticated user.
    """
    project_ids = await get_accessible_project_ids(session, user)

    if not project_ids:
        return HeatmapResponse(repos=[])

    # Per-repo severity counts
    sev_keys = ("critical", "high", "medium", "low", "info")
    proj_stmt = (
        select(
            Project.id,
            Project.name,
            *[
                func.coalesce(
                    func.sum(case((Finding.severity == sev, 1), else_=0)),
                    0,
                ).label(f"{sev}_count")
                for sev in sev_keys
            ],
        )
        .select_from(Project)
        .outerjoin(Finding, Finding.project_id == Project.id)
        .where(Project.id.in_(project_ids))
        .group_by(Project.id, Project.name)
    )

    result = await session.execute(proj_stmt)
    rows = result.fetchall()

    repos = [
        HeatMapEntry(
            project_id=str(row[0]),
            project_name=row[1],
            critical=int(row[2]),
            high=int(row[3]),
            medium=int(row[4]),
            low=int(row[5]),
            info=int(row[6]),
        )
        for row in rows
    ]

    return HeatmapResponse(repos=repos)
