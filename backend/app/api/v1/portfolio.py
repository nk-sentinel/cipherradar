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
# Heatmap schemas
# ---------------------------------------------------------------------------


class HeatmapGroup(CamelCaseModel):
    """A single group entry in the heatmap response."""

    name: str
    project_count: int = Field(ge=0, default=0)
    critical_count: int = Field(ge=0, default=0)
    high_count: int = Field(ge=0, default=0)


class HeatmapResponse(CamelCaseModel):
    """Portfolio heatmap: groups with project and severity counts."""

    groups: list[HeatmapGroup]

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
    """Portfolio heatmap: group-level aggregation of project counts and severity.

    Returns a list of groups with the number of projects and critical/high
    finding counts for each. Group-scoped to the authenticated user.
    """
    project_ids = await get_accessible_project_ids(session, user)

    if not project_ids:
        return HeatmapResponse(groups=[])

    # Get projects with their group info
    from app.models.project import Group

    proj_stmt = (
        select(
            Group.name.label("group_name"),
            func.count(Project.id.distinct()).label("project_count"),
            func.coalesce(
                func.sum(case((Finding.severity == "critical", 1), else_=0)),
                0,
            ).label("critical_count"),
            func.coalesce(
                func.sum(case((Finding.severity == "high", 1), else_=0)),
                0,
            ).label("high_count"),
        )
        .select_from(Project)
        .join(Group, Project.group_id == Group.id)
        .outerjoin(Finding, Finding.project_id == Project.id)
        .where(Project.id.in_(project_ids))
        .group_by(Group.name)
    )

    try:
        result = await session.execute(proj_stmt)
        rows = result.fetchall()
    except Exception:
        # Fallback: simpler query without finding aggregation
        simple_stmt = (
            select(
                Group.name.label("group_name"),
                func.count(Project.id.distinct()).label("project_count"),
            )
            .select_from(Project)
            .join(Group, Project.group_id == Group.id)
            .where(Project.id.in_(project_ids))
            .group_by(Group.name)
        )
        result = await session.execute(simple_stmt)
        rows = result.fetchall()
        return HeatmapResponse(
            groups=[
                HeatmapGroup(
                    name=row.group_name,
                    project_count=row.project_count,
                    critical_count=0,
                    high_count=0,
                )
                for row in rows
            ]
        )

    return HeatmapResponse(
        groups=[
            HeatmapGroup(
                name=row.group_name,
                project_count=row.project_count,
                critical_count=int(row.critical_count),
                high_count=int(row.high_count),
            )
            for row in rows
        ]
    )
