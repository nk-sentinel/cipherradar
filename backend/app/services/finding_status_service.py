"""Finding status management service (D14, D17).

Handles status transitions, RBAC enforcement, assignment,
history recording, and audit logging for findings.

Usage::

    from app.services.finding_status_service import finding_status_service

    await finding_status_service.change_status(
        finding_id=fid, new_status="in_review", actor=user, session=session,
    )
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.auth.roles import Role
from app.models.finding import Finding
from app.models.finding_status_history import FindingStatusHistory
from app.models.notification import Notification
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

# ---------------------------------------------------------------------------
# Valid transitions (D14)
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[str, list[str]] = {
    "open": ["in_review", "in_progress", "resolved", "risk_accepted", "false_positive"],
    "in_review": ["open", "in_progress", "resolved", "risk_accepted", "false_positive"],
    "in_progress": ["open", "in_review", "resolved"],
    "resolved": ["open"],
    "risk_accepted": ["open"],
    "false_positive": ["open"],
}

# ---------------------------------------------------------------------------
# RBAC per target status (D17)
# ---------------------------------------------------------------------------

STATUS_ROLE_MAP: dict[str, list[str]] = {
    "open": [
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
        Role.TEAM_MANAGER, Role.DEVELOPER,
    ],
    "in_review": [
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
        Role.TEAM_MANAGER, Role.DEVELOPER,
    ],
    "in_progress": [
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
        Role.TEAM_MANAGER, Role.DEVELOPER,
    ],
    "resolved": [
        Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ENGINEER,
    ],
    "risk_accepted": [
        Role.ORG_ADMIN, Role.SECURITY_MANAGER,
    ],
    "false_positive": [
        Role.ORG_ADMIN, Role.SECURITY_MANAGER,
    ],
}

# Statuses that require a mandatory reason
_REASON_REQUIRED_STATUSES = frozenset({"risk_accepted", "false_positive"})

# Reversal statuses — going from RA/FP back to open also requires reason
_REVERSAL_FROM = frozenset({"risk_accepted", "false_positive"})


class FindingStatusService:
    """Manages finding status transitions, assignment, and history."""

    async def change_status(
        self,
        finding_id: uuid.UUID,
        new_status: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
        *,
        reason: str | None = None,
        reason_category: str | None = None,
        review_date: str | None = None,
    ) -> Finding:
        """Change a finding's status with full validation.

        Steps:
        1. Load finding
        2. Validate transition
        3. Check fine-grained RBAC
        4. Validate mandatory fields (reason for RA/FP)
        5. Update finding
        6. Record history
        7. Log audit
        8. Return updated finding
        """
        finding = await self._load_finding(finding_id, actor, session)
        old_status = finding.status

        # Validate transition
        allowed = VALID_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            msg = f"Invalid transition from '{old_status}' to '{new_status}'"
            raise ValueError(msg)

        # Fine-grained RBAC
        allowed_roles = STATUS_ROLE_MAP.get(new_status, [])
        if actor.role not in allowed_roles:
            msg = f"Insufficient role '{actor.role}' for status '{new_status}'"
            raise PermissionError(msg)

        # Mandatory reason checks
        if new_status in _REASON_REQUIRED_STATUSES and not reason:
            msg = f"Reason is required when setting status to '{new_status}'"
            raise ValueError(msg)

        if old_status in _REVERSAL_FROM and new_status == "open" and not reason:
            msg = f"Reason is required when reverting from '{old_status}' to 'open'"
            raise ValueError(msg)

        # Update finding
        finding.status = new_status

        # Record history
        history = FindingStatusHistory(
            org_id=finding.org_id,
            finding_id=finding.id,
            changed_by=uuid.UUID(actor.user_id),
            old_status=old_status,
            new_status=new_status,
            reason=reason,
        )
        session.add(history)

        # Audit log
        await audit_service.log(
            action_type="finding.status_change",
            user_id=uuid.UUID(actor.user_id),
            org_id=finding.org_id,
            resource_type="finding",
            resource_id=finding.id,
            details={
                "old_status": old_status,
                "new_status": new_status,
                "reason": reason,
            },
            session=session,
        )

        await session.flush()
        return finding

    async def get_history(
        self,
        finding_id: uuid.UUID,
        session: AsyncSession,
        *,
        page: int = 1,
        per_page: int = 25,
    ):
        """Return paginated status history for a finding."""
        from app.services.pagination_service import paginate

        stmt = (
            select(FindingStatusHistory)
            .where(FindingStatusHistory.finding_id == finding_id)
            .order_by(FindingStatusHistory.created_at.desc())
        )
        return await paginate(query=stmt, page=page, per_page=per_page, session=session)

    async def assign(
        self,
        finding_id: uuid.UUID,
        assignee_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> Finding:
        """Assign a finding to a user.

        Developer can only self-assign. Auto-transitions to in_review
        if current status is open.
        """
        finding = await self._load_finding(finding_id, actor, session)

        # Developer self-assign check
        if actor.role == Role.DEVELOPER and str(assignee_id) != actor.user_id:
            msg = "Developers can only assign findings to themselves (self-assign)"
            raise PermissionError(msg)

        finding.assigned_to = assignee_id

        # Auto-transition to in_review if currently open
        old_status = finding.status
        if finding.status == "open":
            finding.status = "in_review"

            # Record history for auto-transition
            history = FindingStatusHistory(
                org_id=finding.org_id,
                finding_id=finding.id,
                changed_by=uuid.UUID(actor.user_id),
                old_status=old_status,
                new_status="in_review",
                reason="Auto-transitioned on assignment",
            )
            session.add(history)

        # Create notification for assignee (D17)
        notification = Notification(
            user_id=assignee_id,
            org_id=finding.org_id,
            trigger_type="finding_assigned",
            severity="info",
            title=f"Finding assigned to you: {getattr(finding, 'name', 'Unknown')}",
            message=f"A finding has been assigned to you by {actor.user_id}.",
            link=f"/findings/{finding.id}",
        )
        session.add(notification)

        # Audit log
        await audit_service.log(
            action_type="finding.assigned",
            user_id=uuid.UUID(actor.user_id),
            org_id=finding.org_id,
            resource_type="finding",
            resource_id=finding.id,
            details={
                "assignee_id": str(assignee_id),
                "old_status": old_status,
                "new_status": finding.status,
            },
            session=session,
        )

        await session.flush()
        return finding

    async def _load_finding(
        self,
        finding_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> Finding:
        """Load a finding, ensuring it exists and belongs to the actor's org."""
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


# Module-level singleton
finding_status_service = FindingStatusService()
