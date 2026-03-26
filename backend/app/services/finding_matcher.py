"""Cross-scan finding matcher service (ADR-034).

Correlates new scan findings with existing findings in the database
using fingerprints. Determines which findings are new, which match
existing ones, and which existing findings should be resolved.

Usage::

    from app.services.finding_matcher import finding_matcher

    result = await finding_matcher.match(project_id, new_findings, session)
    # result.matched  — existing findings updated from new scan
    # result.new      — brand-new findings to create
    # result.resolved — existing findings no longer present
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models.finding import Finding

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# Statuses that should auto-resolve when a finding disappears from a scan
_AUTO_RESOLVE_STATUSES = frozenset({"open", "in_review", "in_progress"})

# Statuses that are sticky — never auto-changed by the matcher
_STICKY_STATUSES = frozenset({"false_positive", "risk_accepted"})


@dataclass
class MatchResult:
    """Result of matching new scan findings against existing DB findings.

    Attributes
    ----------
    matched:
        Pairs of (new_finding_dict, existing_Finding) where the fingerprint
        matched. The existing Finding has already been updated in-place
        (line number, snippet, etc.) but its status is preserved — unless
        it was ``resolved``, in which case it is reopened to ``open``.
    new:
        Finding dicts from the new scan that have no corresponding DB entry.
        The caller should create new ``Finding`` rows with ``status='open'``.
    resolved:
        Existing ``Finding`` objects whose fingerprints were *not* present
        in the new scan **and** whose status is auto-resolvable
        (open / in_review / in_progress). The caller should set their
        status to ``resolved``.
    """

    matched: list[tuple[dict, Finding]] = field(default_factory=list)
    new: list[dict] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)


class FindingMatcher:
    """Correlate new scan findings with existing DB findings by fingerprint."""

    async def match(
        self,
        project_id: uuid.UUID,
        new_findings: list[dict],
        session: AsyncSession,
    ) -> MatchResult:
        """Match new scan findings against existing findings in DB.

        Parameters
        ----------
        project_id:
            The project whose findings to match against.
        new_findings:
            List of finding dicts from the CLI scan. Each dict must contain
            at least a ``fingerprint`` key.
        session:
            SQLAlchemy async session for DB queries.

        Returns
        -------
        MatchResult
            Categorised findings: matched, new, and resolved.
        """
        # 1. Load existing findings for project (all statuses — we need
        #    resolved ones too for reopen detection)
        existing = await self._load_existing(project_id, session)

        # 2. Build index by fingerprint
        existing_by_fp: dict[str, Finding] = {}
        for f in existing:
            if f.fingerprint:
                existing_by_fp[f.fingerprint] = f

        result = MatchResult()
        matched_fingerprints: set[str] = set()

        # 3. Process each new finding
        for new_f in new_findings:
            fp = new_f.get("fingerprint")
            if not fp:
                # No fingerprint — treat as new
                result.new.append(new_f)
                continue

            existing_f = existing_by_fp.get(fp)
            if existing_f is not None:
                matched_fingerprints.add(fp)
                self._update_matched(existing_f, new_f)
                result.matched.append((new_f, existing_f))
            else:
                result.new.append(new_f)

        # 4. Process unmatched existing findings
        for fp, existing_f in existing_by_fp.items():
            if fp in matched_fingerprints:
                continue

            if existing_f.status in _AUTO_RESOLVE_STATUSES:
                result.resolved.append(existing_f)
            # Sticky statuses (false_positive, risk_accepted) and already
            # resolved findings are left untouched.

        return result

    async def _load_existing(
        self,
        project_id: uuid.UUID,
        session: AsyncSession,
    ) -> list[Finding]:
        """Load all findings for a project (including resolved for reopen)."""
        stmt = select(Finding).where(Finding.project_id == project_id)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    def _update_matched(self, existing: Finding, new_f: dict) -> None:
        """Update an existing finding with data from the new scan.

        Preserves status unless the finding was previously resolved,
        in which case it is reopened.
        """
        # Update location (line may have shifted)
        if "location_line" in new_f:
            existing.location_line = new_f["location_line"]
        if "location_file" in new_f:
            existing.location_file = new_f["location_file"]

        # Reopen if previously resolved
        if existing.status == "resolved":
            existing.status = "open"
            existing.reopen_count = (existing.reopen_count or 0) + 1
            existing.last_reopened_at = datetime.now(timezone.utc)


# Module-level singleton
finding_matcher = FindingMatcher()
