"""Schemas for enhanced audit log endpoints (D28)."""

from __future__ import annotations

from pydantic import Field

from app.schemas.base import CamelCaseModel


class AuditLogEntryEnhanced(CamelCaseModel):
    """An audit log entry from the database."""

    id: str
    timestamp: str
    user_id: str | None = None
    action_type: str
    resource_type: str
    resource_id: str | None = None
    details: dict | None = None
    ip_address: str | None = None


class AuditLogQueryResponse(CamelCaseModel):
    """Paginated audit log response with filters."""

    items: list[AuditLogEntryEnhanced]
    total: int
    page: int
    per_page: int
