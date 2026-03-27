"""Audit log query service — filtered pagination, CSV export, webhook (D28).

Provides rich querying capabilities for the audit log with filtering,
CSV export for compliance purposes, and webhook forwarding.
"""

from __future__ import annotations

import csv
import io
import logging
import uuid as _uuid
from datetime import datetime
from typing import TYPE_CHECKING

import httpx
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.services.pagination_service import paginate

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AuditLogQueryService:
    """Rich querying and export for the audit log."""

    async def query(
        self,
        org_id: str,
        session: AsyncSession,
        *,
        page: int = 1,
        per_page: int = 25,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        user_id: str | None = None,
        action_type: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> dict:
        """Filtered, paginated query of the audit log."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.org_id == _uuid.UUID(org_id))
        )

        if date_from:
            stmt = stmt.where(AuditLog.created_at >= date_from)
        if date_to:
            stmt = stmt.where(AuditLog.created_at <= date_to)
        if user_id:
            stmt = stmt.where(AuditLog.user_id == _uuid.UUID(user_id))
        if action_type:
            stmt = stmt.where(AuditLog.action_type == action_type)
        if resource_type:
            stmt = stmt.where(AuditLog.resource_type == resource_type)
        if resource_id:
            stmt = stmt.where(AuditLog.resource_id == _uuid.UUID(resource_id))

        stmt = stmt.order_by(AuditLog.created_at.desc())

        result = await paginate(query=stmt, page=page, per_page=per_page, session=session)

        items = [
            {
                "id": str(entry.id),
                "timestamp": entry.created_at.isoformat() if entry.created_at else "",
                "user_id": str(entry.user_id) if entry.user_id else None,
                "action_type": entry.action_type,
                "resource_type": entry.resource_type,
                "resource_id": str(entry.resource_id) if entry.resource_id else None,
                "details": entry.details,
                "ip_address": entry.ip_address,
            }
            for entry in result.items
        ]

        return {
            "items": items,
            "total": result.total,
            "page": result.page,
            "per_page": result.per_page,
        }

    async def export_csv(
        self,
        org_id: str,
        session: AsyncSession,
        *,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        user_id: str | None = None,
        action_type: str | None = None,
    ) -> str:
        """Export filtered audit log as CSV string."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.org_id == _uuid.UUID(org_id))
        )

        if date_from:
            stmt = stmt.where(AuditLog.created_at >= date_from)
        if date_to:
            stmt = stmt.where(AuditLog.created_at <= date_to)
        if user_id:
            stmt = stmt.where(AuditLog.user_id == _uuid.UUID(user_id))
        if action_type:
            stmt = stmt.where(AuditLog.action_type == action_type)

        stmt = stmt.order_by(AuditLog.created_at.desc()).limit(10000)  # safety limit

        result = await session.execute(stmt)
        entries = result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "timestamp", "user_id", "action_type",
            "resource_type", "resource_id", "details", "ip_address",
        ])

        for entry in entries:
            writer.writerow([
                str(entry.id),
                entry.created_at.isoformat() if entry.created_at else "",
                str(entry.user_id) if entry.user_id else "",
                entry.action_type,
                entry.resource_type,
                str(entry.resource_id) if entry.resource_id else "",
                str(entry.details) if entry.details else "",
                entry.ip_address or "",
            ])

        return output.getvalue()

    async def forward_to_webhook(
        self,
        webhook_url: str,
        entry: dict,
    ) -> bool:
        """Forward an audit log entry to a webhook URL.

        Returns True if webhook responded with 2xx, False otherwise.
        """
        if not webhook_url:
            return False

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    webhook_url,
                    json={
                        "event": "audit_log.new_entry",
                        "data": entry,
                    },
                    headers={"Content-Type": "application/json"},
                )
            if 200 <= resp.status_code < 300:
                return True
            logger.warning(
                "Audit webhook returned %d for %s", resp.status_code, webhook_url,
            )
            return False
        except httpx.HTTPError:
            logger.warning("Audit webhook failed for %s", webhook_url, exc_info=True)
            return False


audit_log_query_service = AuditLogQueryService()
