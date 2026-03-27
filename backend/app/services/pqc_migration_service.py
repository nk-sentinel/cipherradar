"""PQC migration progress service — aggregate quantum readiness metrics (D23).

Computes post-quantum cryptography migration progress:
- Overall percentages: vulnerable / safe / unknown
- Per-algorithm-family progress (RSA, ECDSA, AES, etc.)
- Lagging projects with highest vulnerable percentages
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.models.finding import Finding
from app.schemas.pqc_migration import (
    AlgorithmFamilyProgress,
    LaggingProject,
    MigrationOverview,
    PQCMigrationResponse,
)

logger = logging.getLogger(__name__)

# quantum_status values that mean "vulnerable"
VULNERABLE_STATUSES = {"vulnerable", "broken"}
SAFE_STATUSES = {"safe", "quantum-safe"}


class PQCMigrationService:
    """Compute PQC migration progress from findings."""

    def compute_overview(self, findings: list[Any]) -> dict[str, Any]:
        """Compute high-level migration percentages.

        Args:
            findings: List of Finding-like objects with quantum_status.

        Returns:
            Dict with total, vulnerable, safe, unknown counts and percentages.
        """
        total = len(findings)
        vulnerable = sum(1 for f in findings if f.quantum_status in VULNERABLE_STATUSES)
        safe = sum(1 for f in findings if f.quantum_status in SAFE_STATUSES)
        unknown = total - vulnerable - safe

        if total == 0:
            return {
                "total_findings": 0,
                "vulnerable": 0,
                "safe": 0,
                "unknown": 0,
                "percent_vulnerable": 0.0,
                "percent_safe": 0.0,
                "percent_unknown": 0.0,
            }

        return {
            "total_findings": total,
            "vulnerable": vulnerable,
            "safe": safe,
            "unknown": unknown,
            "percent_vulnerable": round(vulnerable / total * 100, 2),
            "percent_safe": round(safe / total * 100, 2),
            "percent_unknown": round(unknown / total * 100, 2),
        }

    def compute_families(self, findings: list[Any]) -> list[dict[str, Any]]:
        """Group findings by algorithm family and compute per-family progress.

        Reads ``properties.algorithm_family`` from each finding. Findings
        without an algorithm_family are grouped under "Other".

        Args:
            findings: List of Finding-like objects.

        Returns:
            List of family progress dicts sorted by vulnerable count desc.
        """
        families: dict[str, dict[str, int]] = defaultdict(
            lambda: {"total": 0, "vulnerable": 0, "safe": 0, "unknown": 0}
        )

        for f in findings:
            props = f.properties or {}
            family = props.get("algorithm_family", "Other")
            families[family]["total"] += 1
            if f.quantum_status in VULNERABLE_STATUSES:
                families[family]["vulnerable"] += 1
            elif f.quantum_status in SAFE_STATUSES:
                families[family]["safe"] += 1
            else:
                families[family]["unknown"] += 1

        result = []
        for name, counts in families.items():
            total = counts["total"]
            percent_migrated = round(counts["safe"] / total * 100, 2) if total > 0 else 0.0
            result.append({
                "family": name,
                "total": total,
                "vulnerable": counts["vulnerable"],
                "safe": counts["safe"],
                "unknown": counts["unknown"],
                "percent_migrated": percent_migrated,
            })

        # Sort by most vulnerable first
        result.sort(key=lambda x: x["vulnerable"], reverse=True)
        return result

    def compute_lagging_projects(
        self,
        findings: list[Any],
        *,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Identify projects with the highest percentage of vulnerable findings.

        Args:
            findings: List of Finding-like objects.
            limit: Maximum number of lagging projects to return.

        Returns:
            List of lagging project dicts sorted by percent_vulnerable desc.
        """
        projects: dict[str, dict[str, Any]] = {}

        for f in findings:
            pid = str(f.project_id)
            if pid not in projects:
                project_name = f.project.name if f.project else "Unknown"
                projects[pid] = {
                    "project_id": pid,
                    "project_name": project_name,
                    "vulnerable_count": 0,
                    "total_count": 0,
                }
            projects[pid]["total_count"] += 1
            if f.quantum_status in VULNERABLE_STATUSES:
                projects[pid]["vulnerable_count"] += 1

        # Only include projects that have at least one vulnerable finding
        lagging = []
        for p in projects.values():
            if p["vulnerable_count"] > 0:
                p["percent_vulnerable"] = round(
                    p["vulnerable_count"] / p["total_count"] * 100, 2
                )
                lagging.append(p)

        lagging.sort(key=lambda x: x["percent_vulnerable"], reverse=True)
        return lagging[:limit]

    async def get_migration_progress(
        self,
        session: AsyncSession,
        org_id: str,
        *,
        project_ids: list[uuid.UUID] | None = None,
    ) -> PQCMigrationResponse:
        """Query findings and compute full PQC migration progress.

        Args:
            session: Async database session.
            org_id: Organisation UUID string for tenant scoping.
            project_ids: Accessible project IDs for RBAC filtering.

        Returns:
            PQCMigrationResponse with overview, families, and lagging projects.
        """
        stmt = (
            select(Finding)
            .options(joinedload(Finding.project))
            .where(Finding.org_id == uuid.UUID(org_id))
        )

        if project_ids is not None:
            stmt = stmt.where(Finding.project_id.in_(project_ids))

        result = await session.execute(stmt)
        findings = list(result.scalars().unique().all())

        overview_data = self.compute_overview(findings)
        families_data = self.compute_families(findings)
        lagging_data = self.compute_lagging_projects(findings)

        return PQCMigrationResponse(
            overview=MigrationOverview(**overview_data),
            families=[AlgorithmFamilyProgress(**f) for f in families_data],
            lagging_projects=[LaggingProject(**lp) for lp in lagging_data],
        )


pqc_migration_service = PQCMigrationService()
