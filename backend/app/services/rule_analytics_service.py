"""Rule effectiveness analytics service (D16).

Computes per-rule metrics: FP rate, RA rate, fix rate, MTTR, and trend data
from findings and status history within a configurable time window.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import case, func, select

from app.models.finding import Finding
from app.models.finding_status_history import FindingStatusHistory
from app.models.scan import Scan
from app.schemas.rule_analytics import RuleAnalytics, RuleSummary, TrendPoint

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Statuses considered "active" (open or in-progress but not resolved/accepted/fp)
_ACTIVE_STATUSES = frozenset({"open", "in_review", "in_progress"})


def _parse_time_window(window: str) -> timedelta:
    """Parse a time window string like '30d', '90d', '7d' into a timedelta."""
    match = re.match(r"^(\d+)d$", window.strip())
    if not match:
        return timedelta(days=90)  # default
    return timedelta(days=int(match.group(1)))


class RuleAnalyticsService:
    """Computes rule effectiveness metrics from findings data."""

    async def get_rule_analytics(
        self,
        rule_id: str,
        time_window: str,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> RuleAnalytics:
        """Compute full analytics for a single rule.

        Returns FP rate, RA rate, fix rate, MTTR, and per-scan trend.
        """
        cutoff = datetime.now(UTC) - _parse_time_window(time_window)

        # Fetch all findings for this rule within the time window
        stmt = select(Finding).where(
            Finding.rule_id == rule_id,
            Finding.org_id == org_id,
            Finding.created_at >= cutoff,
        )
        result = await session.execute(stmt)
        findings = list(result.scalars().all())

        total = len(findings)
        if total == 0:
            return RuleAnalytics(
                rule_id=rule_id,
                total_findings=0,
                active_findings=0,
                fp_rate=0.0,
                ra_rate=0.0,
                fix_rate=0.0,
                mttr_seconds=None,
                trend=[],
                time_window=time_window,
            )

        # Count by status
        active = sum(1 for f in findings if f.status in _ACTIVE_STATUSES)
        fp_count = sum(1 for f in findings if f.status == "false_positive")
        ra_count = sum(1 for f in findings if f.status == "risk_accepted")
        resolved_count = sum(1 for f in findings if f.status == "resolved")

        fp_rate = (fp_count / total) * 100
        ra_rate = (ra_count / total) * 100
        fix_rate = (resolved_count / total) * 100

        # MTTR: avg time from created_at to last status change to "resolved"
        # Exclude RA and FP findings
        mttr_seconds = await self._compute_mttr(
            rule_id=rule_id,
            org_id=org_id,
            cutoff=cutoff,
            session=session,
        )

        # Trend: findings per scan
        trend = await self._compute_trend(
            rule_id=rule_id,
            org_id=org_id,
            cutoff=cutoff,
            session=session,
        )

        return RuleAnalytics(
            rule_id=rule_id,
            total_findings=total,
            active_findings=active,
            fp_rate=round(fp_rate, 2),
            ra_rate=round(ra_rate, 2),
            fix_rate=round(fix_rate, 2),
            mttr_seconds=round(mttr_seconds, 2) if mttr_seconds is not None else None,
            trend=trend,
            time_window=time_window,
        )

    async def get_rules_summary(
        self,
        org_id: uuid.UUID,
        time_window: str,
        session: AsyncSession,
    ) -> list[RuleSummary]:
        """Compute summary analytics for all rules in the org."""
        cutoff = datetime.now(UTC) - _parse_time_window(time_window)

        # Aggregate findings by rule_id
        stmt = (
            select(
                Finding.rule_id,
                func.count(Finding.id).label("total"),
                func.count(
                    case((Finding.status == "false_positive", Finding.id))
                ).label("fp_count"),
                func.count(
                    case((Finding.status == "resolved", Finding.id))
                ).label("resolved_count"),
            )
            .where(
                Finding.org_id == org_id,
                Finding.created_at >= cutoff,
            )
            .group_by(Finding.rule_id)
            .order_by(func.count(Finding.id).desc())
        )
        result = await session.execute(stmt)
        rows = result.all()

        summaries = []
        for row in rows:
            total = row.total
            fp_rate = (row.fp_count / total) * 100 if total > 0 else 0.0
            fix_rate = (row.resolved_count / total) * 100 if total > 0 else 0.0
            warning = fp_rate > 50 or (fix_rate < 10 and total > 0)

            summaries.append(
                RuleSummary(
                    rule_id=row.rule_id,
                    total_findings=total,
                    fp_rate=round(fp_rate, 2),
                    fix_rate=round(fix_rate, 2),
                    mttr_seconds=None,  # computed per-rule on demand
                    warning=warning,
                )
            )

        return summaries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _compute_mttr(
        self,
        rule_id: str,
        org_id: uuid.UUID,
        cutoff: datetime,
        session: AsyncSession,
    ) -> float | None:
        """Compute mean time to resolution (seconds) for resolved findings.

        Excludes risk_accepted and false_positive findings.
        MTTR = avg(resolved_at - created_at) for findings that reached "resolved".
        """
        # Find findings that were resolved (not RA/FP)
        resolved_findings_stmt = select(Finding).where(
            Finding.rule_id == rule_id,
            Finding.org_id == org_id,
            Finding.created_at >= cutoff,
            Finding.status == "resolved",
        )
        result = await session.execute(resolved_findings_stmt)
        resolved_findings = list(result.scalars().all())

        if not resolved_findings:
            return None

        # For each resolved finding, find the first "resolved" status change
        total_seconds = 0.0
        count = 0

        for finding in resolved_findings:
            history_stmt = (
                select(FindingStatusHistory.created_at)
                .where(
                    FindingStatusHistory.finding_id == finding.id,
                    FindingStatusHistory.new_status == "resolved",
                )
                .order_by(FindingStatusHistory.created_at.desc())
                .limit(1)
            )
            history_result = await session.execute(history_stmt)
            resolved_at = history_result.scalar_one_or_none()

            if resolved_at is not None:
                delta = (resolved_at - finding.created_at).total_seconds()
                total_seconds += delta
                count += 1

        if count == 0:
            return None

        return total_seconds / count

    async def _compute_trend(
        self,
        rule_id: str,
        org_id: uuid.UUID,
        cutoff: datetime,
        session: AsyncSession,
    ) -> list[TrendPoint]:
        """Compute findings-per-scan trend for a rule."""
        stmt = (
            select(
                Finding.scan_id,
                func.count(Finding.id).label("count"),
                func.min(Scan.created_at).label("scanned_at"),
            )
            .join(Scan, Finding.scan_id == Scan.id)
            .where(
                Finding.rule_id == rule_id,
                Finding.org_id == org_id,
                Finding.created_at >= cutoff,
            )
            .group_by(Finding.scan_id)
            .order_by(func.min(Scan.created_at))
        )
        result = await session.execute(stmt)
        rows = result.all()

        return [
            TrendPoint(
                scan_id=row.scan_id,
                count=row.count,
                scanned_at=row.scanned_at,
            )
            for row in rows
        ]


# Module-level singleton
rule_analytics_service = RuleAnalyticsService()
