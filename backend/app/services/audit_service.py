"""Centralized audit logging service for tracking security-relevant actions.

Usage::

    from app.services.audit_service import audit_service

    await audit_service.log(
        action_type="user.role_change",
        user_id=current_user.id,
        org_id=current_user.org_id,
        resource_type="user",
        resource_id=target_user.id,
        details={"old_role": "developer", "new_role": "security_engineer"},
        session=session,
    )
"""

from __future__ import annotations

import asyncio
import logging
import uuid as _uuid
from typing import TYPE_CHECKING

from app.models.audit_log import AuditLog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AuditService:
    """Centralized audit logger.

    All security-relevant actions across the platform should be logged through
    this service to ensure consistent formatting and storage.
    """

    async def _fire_webhook(self, org_id: _uuid.UUID, entry_data: dict) -> None:
        """Forward audit entry to org webhook if configured.

        Runs as a fire-and-forget background task so it never blocks the
        main request path. Errors are logged as warnings but never raised.
        """
        try:
            from app.services.audit_log_query_service import audit_log_query_service

            # Look up org webhook URL from settings.
            # Import here to avoid circular imports at module level.
            from sqlalchemy import text

            from app.db.session import async_session_factory

            webhook_url: str | None = None
            async with async_session_factory() as sess:
                result = await sess.execute(
                    text("SELECT settings FROM organisations WHERE id = :org_id"),
                    {"org_id": org_id},
                )
                row = result.fetchone()
                if row and row[0]:
                    webhook_url = row[0].get("audit_webhook_url")

            if not webhook_url:
                return

            success = await audit_log_query_service.forward_to_webhook(
                webhook_url=webhook_url,
                entry=entry_data,
            )
            if success:
                logger.info(
                    "Audit webhook sent",
                    extra={"extra_fields": {
                        "org_id": str(org_id),
                        "action_type": entry_data.get("action_type"),
                    }},
                )
            else:
                logger.warning(
                    "Audit webhook failed",
                    extra={"extra_fields": {
                        "org_id": str(org_id),
                        "webhook_url": webhook_url,
                    }},
                )
        except Exception:
            logger.warning("Audit webhook error", exc_info=True)

    async def log(
        self,
        action_type: str,
        org_id: _uuid.UUID,
        resource_type: str,
        user_id: _uuid.UUID | None = None,
        resource_id: _uuid.UUID | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session: AsyncSession | None = None,
    ) -> None:
        """Record an audit log entry.

        Parameters
        ----------
        action_type:
            Dotted action identifier, e.g. ``"user.role_change"``,
            ``"finding.status_change"``, ``"scan.started"``.
        org_id:
            UUID of the organisation context.
        resource_type:
            Entity kind being acted upon (``"user"``, ``"finding"``, etc.).
        user_id:
            Optional UUID of the user performing the action.
        resource_id:
            Optional UUID of the target resource.
        details:
            Optional JSON-serialisable dict with action-specific metadata.
        ip_address:
            Optional IP address of the request origin.
        user_agent:
            Optional User-Agent header value.
        session:
            SQLAlchemy ``AsyncSession`` used for persistence.
        """
        if session is None:
            msg = "session is required for audit logging"
            raise ValueError(msg)

        entry = AuditLog(
            action_type=action_type,
            user_id=user_id,
            org_id=org_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add(entry)
        await session.flush()

        entry_data = {
            "action_type": action_type,
            "user_id": str(user_id) if user_id else None,
            "org_id": str(org_id),
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id else None,
            "details": details,
        }

        logger.info(
            "Audit entry created",
            extra={"extra_fields": entry_data},
        )

        # Fire webhook in background — never block the caller
        asyncio.create_task(self._fire_webhook(org_id, entry_data))


# Module-level singleton for dependency injection
audit_service = AuditService()
