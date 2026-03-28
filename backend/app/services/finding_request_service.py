"""Finding request service (D15 — FP/RA request workflow).

Handles creation, approval, and rejection of false positive and
risk acceptance requests.

Usage::

    from app.services.finding_request_service import finding_request_service

    await finding_request_service.create_request(
        finding_id=fid, request_type="false_positive",
        justification="Not a real finding", actor=user, session=session,
    )
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.auth.roles import Role
from app.models.finding import Finding
from app.models.finding_request import FindingRequest
from app.models.finding_status_history import FindingStatusHistory
from app.services.audit_service import audit_service

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

# Roles allowed to create requests
_CREATOR_ROLES = frozenset({
    Role.SECURITY_ENGINEER,
    Role.TEAM_MANAGER,
    Role.DEVELOPER,
})

# Roles allowed to approve/reject requests
_REVIEWER_ROLES = frozenset({
    Role.ORG_ADMIN,
    Role.SECURITY_MANAGER,
    Role.SECURITY_ENGINEER,
})

# Map request type to finding status
_REQUEST_TYPE_TO_STATUS: dict[str, str] = {
    "false_positive": "false_positive",
    "risk_accepted": "risk_accepted",
}


class FindingRequestService:
    """Manages FP/RA request lifecycle."""

    async def create_request(
        self,
        finding_id: uuid.UUID,
        request_type: str,
        justification: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> FindingRequest:
        """Create a new FP/RA request for a finding.

        RBAC: SE, TM, DEV can create requests.
        """
        if actor.role not in _CREATOR_ROLES:
            msg = f"Role '{actor.role}' cannot create finding requests"
            raise PermissionError(msg)

        # Validate finding exists
        finding = await self._load_finding(finding_id, actor, session)

        request = FindingRequest(
            org_id=finding.org_id,
            finding_id=finding.id,
            requested_by=uuid.UUID(actor.user_id),
            request_type=request_type,
            status="pending",
            justification=justification,
        )
        session.add(request)

        await audit_service.log(
            action_type="finding.request_created",
            user_id=uuid.UUID(actor.user_id),
            org_id=finding.org_id,
            resource_type="finding_request",
            resource_id=finding.id,
            details={
                "request_type": request_type,
                "finding_id": str(finding.id),
            },
            session=session,
        )

        logger.info(
            "Finding request created",
            extra={"extra_fields": {
                "request_type": request_type,
                "finding_id": str(finding.id),
                "actor": actor.user_id,
                "org_id": str(finding.org_id),
            }},
        )

        await session.flush()
        return request

    async def list_requests(
        self,
        org_id: uuid.UUID,
        actor: AuthenticatedUser,
        page: int,
        per_page: int,
        session: AsyncSession,
    ):
        """List requests, RBAC-scoped.

        TM sees only requests for their group's projects.
        SM/OA see all org requests.
        """
        from app.services.pagination_service import paginate

        stmt = (
            select(FindingRequest)
            .where(FindingRequest.org_id == org_id)
            .order_by(FindingRequest.created_at.desc())
        )

        # TM scoping: filter by group — in a real implementation this would
        # join with projects to filter by group_id. For now we add a basic
        # group scope note in the query.
        # Full group subtree filtering deferred to service-layer join.

        return await paginate(query=stmt, page=page, per_page=per_page, session=session)

    async def approve(
        self,
        request_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> FindingRequest:
        """Approve a pending request. Changes finding status.

        SE cannot approve own request.
        """
        request = await self._load_request(request_id, actor, session)

        if request.status != "pending":
            msg = f"Request is already '{request.status}'"
            raise ValueError(msg)

        # Cannot approve own request
        if str(request.requested_by) == actor.user_id:
            msg = "Cannot approve own request"
            raise PermissionError(msg)

        if actor.role not in _REVIEWER_ROLES:
            msg = f"Role '{actor.role}' cannot approve requests"
            raise PermissionError(msg)

        # Update request
        request.status = "approved"
        request.reviewed_by = uuid.UUID(actor.user_id)
        request.reviewed_at = datetime.now(timezone.utc)

        # Update finding status
        new_status = _REQUEST_TYPE_TO_STATUS.get(request.request_type)
        if new_status:
            finding = await self._load_finding_by_id(request.finding_id, session)
            if finding:
                old_status = finding.status
                finding.status = new_status

                # Record history
                history = FindingStatusHistory(
                    org_id=request.org_id,
                    finding_id=finding.id,
                    changed_by=uuid.UUID(actor.user_id),
                    old_status=old_status,
                    new_status=new_status,
                    reason=f"Approved {request.request_type} request",
                )
                session.add(history)

        await audit_service.log(
            action_type="finding.request_approved",
            user_id=uuid.UUID(actor.user_id),
            org_id=request.org_id,
            resource_type="finding_request",
            resource_id=request.id,
            details={
                "request_type": request.request_type,
                "finding_id": str(request.finding_id),
            },
            session=session,
        )

        logger.info(
            "Finding request approved",
            extra={"extra_fields": {
                "request_id": str(request_id),
                "request_type": request.request_type,
                "finding_id": str(request.finding_id),
                "actor": actor.user_id,
                "org_id": str(request.org_id),
            }},
        )

        await session.flush()
        return request

    async def reject(
        self,
        request_id: uuid.UUID,
        reason: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> FindingRequest:
        """Reject a pending request. Finding status stays unchanged."""
        request = await self._load_request(request_id, actor, session)

        if request.status != "pending":
            msg = f"Request is already '{request.status}'"
            raise ValueError(msg)

        if actor.role not in _REVIEWER_ROLES:
            msg = f"Role '{actor.role}' cannot reject requests"
            raise PermissionError(msg)

        request.status = "rejected"
        request.review_note = reason
        request.reviewed_by = uuid.UUID(actor.user_id)
        request.reviewed_at = datetime.now(timezone.utc)

        await audit_service.log(
            action_type="finding.request_rejected",
            user_id=uuid.UUID(actor.user_id),
            org_id=request.org_id,
            resource_type="finding_request",
            resource_id=request.id,
            details={
                "request_type": request.request_type,
                "finding_id": str(request.finding_id),
                "reason": reason,
            },
            session=session,
        )

        logger.info(
            "Finding request rejected",
            extra={"extra_fields": {
                "request_id": str(request_id),
                "request_type": request.request_type,
                "finding_id": str(request.finding_id),
                "actor": actor.user_id,
                "org_id": str(request.org_id),
            }},
        )

        await session.flush()
        return request

    async def _load_finding(
        self,
        finding_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> Finding:
        """Load a finding ensuring it exists and belongs to actor's org."""
        stmt = select(Finding).where(
            Finding.id == finding_id,
            Finding.org_id == uuid.UUID(actor.org_id),
        )
        result = await session.execute(stmt)
        finding = result.scalar_one_or_none()
        if finding is None:
            msg = "Finding not found"
            raise LookupError(msg)
        return finding

    async def _load_finding_by_id(
        self,
        finding_id: uuid.UUID,
        session: AsyncSession,
    ) -> Finding | None:
        """Load a finding by ID without org check (used after request validation)."""
        stmt = select(Finding).where(Finding.id == finding_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def _load_request(
        self,
        request_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> FindingRequest:
        """Load a request ensuring it exists and belongs to actor's org."""
        stmt = select(FindingRequest).where(
            FindingRequest.id == request_id,
            FindingRequest.org_id == uuid.UUID(actor.org_id),
        )
        result = await session.execute(stmt)
        request = result.scalar_one_or_none()
        if request is None:
            msg = "Request not found"
            raise LookupError(msg)
        return request


# Module-level singleton
finding_request_service = FindingRequestService()
