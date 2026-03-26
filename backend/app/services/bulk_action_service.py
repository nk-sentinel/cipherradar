"""Bulk action service for findings (D19).

Delegates individual operations to finding_status_service and
finding_request_service. Collects per-finding results.

Usage::

    from app.services.bulk_action_service import bulk_action_service

    result = await bulk_action_service.execute(
        finding_ids=ids, action="assign",
        params={"assignee_id": "..."}, actor=user, session=session,
    )
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.services.finding_request_service import finding_request_service
from app.services.finding_status_service import finding_status_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser


# Supported action names
_SUPPORTED_ACTIONS = frozenset({
    "assign",
    "status_change",
    "mark_fp",
    "mark_ra",
    "raise_fp_request",
    "raise_ra_request",
    "export",
})


@dataclass
class BulkResultItem:
    """Result for a single finding in a bulk operation."""

    finding_id: uuid.UUID
    success: bool
    error: str | None = None


@dataclass
class BulkResult:
    """Aggregate result for a bulk operation."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    results: list[BulkResultItem] = field(default_factory=list)


class BulkActionService:
    """Execute bulk actions on findings with per-item error collection."""

    async def execute(
        self,
        finding_ids: list[uuid.UUID],
        action: str,
        params: dict,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> BulkResult:
        """Execute a bulk action on the given findings.

        Supported actions: assign, status_change, mark_fp, mark_ra,
        raise_fp_request, raise_ra_request, export.
        """
        if action not in _SUPPORTED_ACTIONS:
            msg = f"Unsupported action: '{action}'"
            raise ValueError(msg)

        result = BulkResult(total=len(finding_ids))

        for fid in finding_ids:
            try:
                await self._execute_single(fid, action, params, actor, session)
                result.succeeded += 1
                result.results.append(BulkResultItem(finding_id=fid, success=True))
            except (ValueError, PermissionError, LookupError) as e:
                result.failed += 1
                result.results.append(
                    BulkResultItem(finding_id=fid, success=False, error=str(e))
                )

        return result

    async def _execute_single(
        self,
        finding_id: uuid.UUID,
        action: str,
        params: dict,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> None:
        """Execute a single action on one finding."""
        if action == "assign":
            assignee_id = uuid.UUID(params["assignee_id"])
            await finding_status_service.assign(
                finding_id=finding_id,
                assignee_id=assignee_id,
                actor=actor,
                session=session,
            )

        elif action == "status_change":
            new_status = params["status"]
            await finding_status_service.change_status(
                finding_id=finding_id,
                new_status=new_status,
                actor=actor,
                session=session,
                reason=params.get("reason"),
                reason_category=params.get("reason_category"),
            )

        elif action == "mark_fp":
            await finding_status_service.change_status(
                finding_id=finding_id,
                new_status="false_positive",
                actor=actor,
                session=session,
                reason=params.get("reason", "Marked as false positive via bulk action"),
            )

        elif action == "mark_ra":
            await finding_status_service.change_status(
                finding_id=finding_id,
                new_status="risk_accepted",
                actor=actor,
                session=session,
                reason=params.get("reason", "Marked as risk accepted via bulk action"),
                reason_category=params.get("reason_category", "business_exception"),
            )

        elif action == "raise_fp_request":
            await finding_request_service.create_request(
                finding_id=finding_id,
                request_type="false_positive",
                justification=params.get("justification", "Bulk FP request"),
                actor=actor,
                session=session,
            )

        elif action == "raise_ra_request":
            await finding_request_service.create_request(
                finding_id=finding_id,
                request_type="risk_accepted",
                justification=params.get("justification", "Bulk RA request"),
                actor=actor,
                session=session,
            )

        elif action == "export":
            # Export is a no-op per finding — the caller aggregates results
            pass


# Module-level singleton
bulk_action_service = BulkActionService()
