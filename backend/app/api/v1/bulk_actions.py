"""Bulk actions route (D19).

Provides a single endpoint for executing bulk operations on findings.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.bulk_action import (
    BulkActionRequest,
    BulkActionResponse,
    BulkActionResultItem,
)
from app.services.bulk_action_service import bulk_action_service

router = APIRouter(tags=["bulk-actions"])


@router.post(
    "/findings/bulk",
    response_model=BulkActionResponse,
    dependencies=[
        Depends(
            require_role(
                Role.ORG_ADMIN,
                Role.SECURITY_MANAGER,
                Role.SECURITY_ENGINEER,
                Role.TEAM_MANAGER,
                Role.DEVELOPER,
            )
        )
    ],
)
async def execute_bulk_action(
    body: BulkActionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> BulkActionResponse:
    """Execute a bulk action on multiple findings.

    Supported actions: assign, status_change, mark_fp, mark_ra,
    raise_fp_request, raise_ra_request, export.

    RBAC is enforced per-finding by the underlying services.
    """
    try:
        result = await bulk_action_service.execute(
            finding_ids=body.finding_ids,
            action=body.action,
            params=body.params,
            actor=user,
            session=session,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return BulkActionResponse(
        total=result.total,
        succeeded=result.succeeded,
        failed=result.failed,
        results=[
            BulkActionResultItem(
                finding_id=r.finding_id,
                success=r.success,
                error=r.error,
            )
            for r in result.results
        ],
    )
