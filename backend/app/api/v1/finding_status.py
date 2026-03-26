"""Finding status management routes (D14, D17).

Provides endpoints for changing finding status, viewing status history,
and assigning findings to users.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.finding_status import (
    FindingAssignment,
    FindingStatusHistoryItem,
    FindingStatusHistoryResponse,
    FindingStatusResponse,
    FindingStatusUpdate,
)
from app.services.finding_status_service import finding_status_service

router = APIRouter(tags=["findings"])


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingStatusResponse,
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
async def change_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingStatusResponse:
    """Change a finding's status. RBAC: varies by target status (see D14/D17)."""
    try:
        finding = await finding_status_service.change_status(
            finding_id=finding_id,
            new_status=body.status,
            reason=body.reason,
            reason_category=body.reason_category.value if body.reason_category else None,
            review_date=body.review_date.isoformat() if body.review_date else None,
            actor=user,
            session=session,
        )
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    return FindingStatusResponse.model_validate(finding)


@router.get(
    "/findings/{finding_id}/history",
    response_model=FindingStatusHistoryResponse,
    dependencies=[
        Depends(
            require_role(
                Role.ORG_ADMIN,
                Role.SECURITY_MANAGER,
                Role.SECURITY_ENGINEER,
                Role.TEAM_MANAGER,
                Role.COMPLIANCE_AUDITOR,
                Role.DEVELOPER,
            )
        )
    ],
)
async def get_finding_history(
    finding_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=100),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingStatusHistoryResponse:
    """Get paginated status change history for a finding."""
    result = await finding_status_service.get_history(
        finding_id=finding_id,
        session=session,
        page=page,
        per_page=per_page,
    )
    return FindingStatusHistoryResponse(
        items=[FindingStatusHistoryItem.model_validate(item) for item in result.items],
        total=result.total,
        page=result.page,
        per_page=result.per_page,
    )


@router.patch(
    "/findings/{finding_id}/assign",
    response_model=FindingStatusResponse,
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
async def assign_finding(
    finding_id: uuid.UUID,
    body: FindingAssignment,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingStatusResponse:
    """Assign a finding to a user. Auto-transitions to in_review if open."""
    try:
        finding = await finding_status_service.assign(
            finding_id=finding_id,
            assignee_id=body.assignee_id,
            actor=user,
            session=session,
        )
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    return FindingStatusResponse.model_validate(finding)
