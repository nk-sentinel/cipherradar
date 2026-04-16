"""Rule effectiveness analytics API endpoints (D16).

Provides per-rule metrics including FP rate, fix rate, MTTR, and trend data.
Access restricted to OA, SM, SE roles.
"""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.rule_analytics import RuleAnalytics, RuleSummary
from app.services.rule_analytics_service import rule_analytics_service

router = APIRouter(prefix="/admin/rules", tags=["rule-analytics"])

_analytics_roles = require_role(
    Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
)


# ---------------------------------------------------------------------------
# GET /api/v1/admin/rules/{rule_id}/analytics
# ---------------------------------------------------------------------------


@router.get(
    "/{rule_id}/analytics",
    response_model=RuleAnalytics,
    dependencies=[Depends(_analytics_roles)],
)
async def get_rule_analytics(
    rule_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    time_window: str = Query(default="90d", description="Time window, e.g. 30d, 90d"),
) -> RuleAnalytics:
    """Get effectiveness analytics for a specific rule. RBAC: OA, SM, SE."""
    return await rule_analytics_service.get_rule_analytics(
        rule_id=rule_id,
        time_window=time_window,
        org_id=user.required_org_uuid,
        session=session,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/admin/rules/summary
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    response_model=list[RuleSummary],
    dependencies=[Depends(_analytics_roles)],
)
async def get_rules_summary(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    time_window: str = Query(default="90d", description="Time window, e.g. 30d, 90d"),
) -> list[RuleSummary]:
    """Get summary analytics for all rules. RBAC: OA, SM, SE."""
    return await rule_analytics_service.get_rules_summary(
        org_id=user.required_org_uuid,
        time_window=time_window,
        session=session,
    )
