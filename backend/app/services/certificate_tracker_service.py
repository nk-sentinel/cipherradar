"""Certificate tracker service — query certificate findings and compute expiry status (D23).

Extracts certificate-type findings from the database, parses ``not_valid_after``
from the JSONB ``properties`` column, and computes days remaining and color status:
- green: >90 days
- amber: 30–90 days
- red: <30 days
- black: expired
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.models.finding import Finding
from app.schemas.certificate_tracker import CertificateEntry, CertificateTrackerResponse

logger = logging.getLogger(__name__)


class CertificateTrackerService:
    """Compute certificate expiry status from findings."""

    def compute_status(self, not_after: datetime) -> tuple[str, int]:
        """Return (status_color, days_remaining) for a given expiry date.

        Args:
            not_after: Certificate expiry datetime (timezone-aware).

        Returns:
            Tuple of (color string, integer days remaining).
        """
        now = datetime.now(timezone.utc)
        delta = not_after - now
        days = delta.days

        if days < 0:
            return "black", days
        if days < 30:
            return "red", days
        if days <= 90:
            return "amber", days
        return "green", days

    def build_entries(self, findings: list[Any]) -> list[dict[str, Any]]:
        """Convert finding objects into certificate entry dicts.

        Args:
            findings: List of Finding-like objects with properties JSONB.

        Returns:
            List of dicts suitable for constructing CertificateEntry schemas.
        """
        entries: list[dict[str, Any]] = []
        for f in findings:
            props = f.properties or {}
            not_after_raw = props.get("not_valid_after")
            if not not_after_raw:
                continue

            try:
                if isinstance(not_after_raw, str):
                    not_after = datetime.fromisoformat(not_after_raw)
                else:
                    not_after = not_after_raw
                # Ensure timezone-aware
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                logger.warning("Invalid not_valid_after for finding %s: %s", f.id, not_after_raw)
                continue

            color, days = self.compute_status(not_after)
            entries.append({
                "id": f.id,
                "subject": props.get("subject_name", "Unknown"),
                "issuer": props.get("issuer_name", "Unknown"),
                "not_after": not_after,
                "status_color": color,
                "days_remaining": days,
                "project_name": f.project.name if f.project else "Unknown",
                "project_id": f.project_id,
                "file_path": f.location_file,
            })
        return entries

    async def list_certificates(
        self,
        session: AsyncSession,
        org_id: str,
        *,
        project_ids: list[uuid.UUID] | None = None,
        status_color: str | None = None,
        project_id: uuid.UUID | None = None,
        page: int = 1,
        per_page: int = 25,
    ) -> CertificateTrackerResponse:
        """Query certificate findings and return paginated, filtered results.

        Args:
            session: Async database session.
            org_id: Organisation UUID string for tenant scoping.
            project_ids: Accessible project IDs for RBAC filtering.
            status_color: Filter by status (green, amber, red, black).
            project_id: Filter by specific project.
            page: 1-based page number.
            per_page: Items per page.

        Returns:
            Paginated CertificateTrackerResponse.
        """
        stmt = (
            select(Finding)
            .options(joinedload(Finding.project))
            .where(
                Finding.org_id == uuid.UUID(org_id),
                Finding.asset_type == "certificate",
            )
        )

        if project_ids is not None:
            stmt = stmt.where(Finding.project_id.in_(project_ids))

        if project_id is not None:
            stmt = stmt.where(Finding.project_id == project_id)

        result = await session.execute(stmt)
        findings = result.scalars().unique().all()

        # Build entries and apply status_color filter post-query
        all_entries = self.build_entries(list(findings))

        if status_color:
            all_entries = [e for e in all_entries if e["status_color"] == status_color]

        # Sort by days_remaining ascending (most urgent first)
        all_entries.sort(key=lambda e: e["days_remaining"])

        total = len(all_entries)
        start = (page - 1) * per_page
        page_entries = all_entries[start : start + per_page]

        items = [CertificateEntry(**e) for e in page_entries]

        return CertificateTrackerResponse(
            items=items,
            total=total,
            page=page,
            per_page=per_page,
        )


certificate_tracker_service = CertificateTrackerService()
