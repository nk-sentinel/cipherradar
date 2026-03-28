"""Finding request routes (D15 — FP/RA request workflow).

Provides endpoints for creating, listing, approving, and rejecting
false positive and risk acceptance requests.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user, require_role
from app.auth.roles import Role
from app.db.session import get_session
from app.schemas.finding_request import (
    FindingRequestCreate,
    FindingRequestListResponse,
    FindingRequestReject,
    FindingRequestResponse,
)
from app.services.finding_request_service import finding_request_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["finding-requests"])


@router.post(
    "/findings/{finding_id}/request",
    response_model=FindingRequestResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_role(
                Role.SECURITY_ENGINEER,
                Role.TEAM_MANAGER,
                Role.DEVELOPER,
            )
        )
    ],
)
async def create_finding_request(
    finding_id: uuid.UUID,
    body: FindingRequestCreate,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingRequestResponse:
    """Create a FP/RA request for a finding."""
    try:
        request = await finding_request_service.create_request(
            finding_id=finding_id,
            request_type=body.request_type,
            justification=body.justification,
            actor=user,
            session=session,
        )
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    except PermissionError as e:
        logger.warning(
            "RBAC denied: create finding request",
            extra={"extra_fields": {"user_id": user.user_id, "finding_id": str(finding_id)}},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    logger.info(
        "Finding request created",
        extra={"extra_fields": {
            "finding_id": str(finding_id),
            "request_type": body.request_type,
            "user_id": user.user_id,
        }},
    )
    return FindingRequestResponse.model_validate(request)


@router.get(
    "/requests",
    response_model=FindingRequestListResponse,
    dependencies=[
        Depends(
            require_role(
                Role.ORG_ADMIN,
                Role.SECURITY_MANAGER,
                Role.SECURITY_ENGINEER,
                Role.TEAM_MANAGER,
            )
        )
    ],
)
async def list_requests(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=100),
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingRequestListResponse:
    """List finding requests, paginated and RBAC-scoped."""
    logger.info(
        "Listing finding requests",
        extra={"extra_fields": {"user_id": user.user_id, "org_id": user.org_id}},
    )
    result = await finding_request_service.list_requests(
        org_id=uuid.UUID(user.org_id),
        actor=user,
        page=page,
        per_page=per_page,
        session=session,
    )
    return FindingRequestListResponse(
        items=[FindingRequestResponse.model_validate(item) for item in result.items],
        total=result.total,
        page=result.page,
        per_page=result.per_page,
    )


@router.post(
    "/requests/{request_id}/approve",
    response_model=FindingRequestResponse,
    dependencies=[
        Depends(
            require_role(
                Role.ORG_ADMIN,
                Role.SECURITY_MANAGER,
                Role.SECURITY_ENGINEER,
            )
        )
    ],
)
async def approve_request(
    request_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingRequestResponse:
    """Approve a pending FP/RA request."""
    try:
        request = await finding_request_service.approve(
            request_id=request_id,
            actor=user,
            session=session,
        )
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Request not found",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except PermissionError as e:
        logger.warning(
            "RBAC denied: approve finding request",
            extra={"extra_fields": {"user_id": user.user_id, "request_id": str(request_id)}},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    logger.info(
        "Finding request approved",
        extra={"extra_fields": {"request_id": str(request_id), "user_id": user.user_id}},
    )
    return FindingRequestResponse.model_validate(request)


@router.post(
    "/requests/{request_id}/reject",
    response_model=FindingRequestResponse,
    dependencies=[
        Depends(
            require_role(
                Role.ORG_ADMIN,
                Role.SECURITY_MANAGER,
                Role.SECURITY_ENGINEER,
            )
        )
    ],
)
async def reject_request(
    request_id: uuid.UUID,
    body: FindingRequestReject,
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FindingRequestResponse:
    """Reject a pending FP/RA request."""
    try:
        request = await finding_request_service.reject(
            request_id=request_id,
            reason=body.reason,
            actor=user,
            session=session,
        )
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Request not found",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except PermissionError as e:
        logger.warning(
            "RBAC denied: reject finding request",
            extra={"extra_fields": {"user_id": user.user_id, "request_id": str(request_id)}},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    logger.info(
        "Finding request rejected",
        extra={"extra_fields": {"request_id": str(request_id), "user_id": user.user_id}},
    )
    return FindingRequestResponse.model_validate(request)
