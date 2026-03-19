"""CBOM management service: versioning, diffing, and merging."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.models.scan import Scan, ScanStatus
from app.schemas.cbom import (
    CBOMDiff,
    CBOMDiffItem,
    CBOMVersion,
    ChangeType,
    MergedCBOM,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.cbom import CBOMDocument


class CBOMService:
    """CBOM management: versioning, diff, and merge operations."""

    async def get_versions(self, project_id: uuid.UUID, session: AsyncSession) -> list[CBOMVersion]:
        """Return all CBOM snapshots for a project, ordered by version number.

        Version numbers are assigned based on the chronological order of
        completed scans (earliest completed scan = version 1).
        """
        stmt = (
            select(Scan)
            .where(Scan.project_id == project_id, Scan.status == ScanStatus.COMPLETED)
            .options(joinedload(Scan.cbom_document))
            .order_by(Scan.completed_at.asc())
        )
        result = await session.execute(stmt)
        scans = result.unique().scalars().all()

        versions: list[CBOMVersion] = []
        for idx, scan in enumerate(scans, start=1):
            cbom_doc: CBOMDocument | None = scan.cbom_document
            if cbom_doc is None:
                continue
            versions.append(
                CBOMVersion(
                    scan_id=scan.id,
                    version_number=idx,
                    created_at=scan.created_at,
                    findings_count=scan.findings_count,
                    spec_version=cbom_doc.spec_version,
                )
            )
        return versions

    async def diff(
        self,
        base_scan_id: uuid.UUID,
        head_scan_id: uuid.UUID,
        session: AsyncSession,
    ) -> CBOMDiff:
        """Compare two CBOM documents and return added/removed/changed components.

        Component identity is determined by (name, file, line).  If a component
        exists in both but has different properties, it is reported as *changed*.
        """
        base_cbom = await self._load_cbom_json(base_scan_id, session)
        head_cbom = await self._load_cbom_json(head_scan_id, session)

        base_components = base_cbom.get("components", [])
        head_components = head_cbom.get("components", [])

        base_by_key = self._index_components(base_components)
        head_by_key = self._index_components(head_components)

        base_keys = set(base_by_key.keys())
        head_keys = set(head_by_key.keys())

        added: list[CBOMDiffItem] = []
        removed: list[CBOMDiffItem] = []
        changed: list[CBOMDiffItem] = []

        for key in head_keys - base_keys:
            comp = head_by_key[key]
            added.append(
                CBOMDiffItem(
                    name=comp.get("name", ""),
                    file=self._component_file(comp),
                    line=self._component_line(comp),
                    change_type=ChangeType.ADDED,
                )
            )

        for key in base_keys - head_keys:
            comp = base_by_key[key]
            removed.append(
                CBOMDiffItem(
                    name=comp.get("name", ""),
                    file=self._component_file(comp),
                    line=self._component_line(comp),
                    change_type=ChangeType.REMOVED,
                )
            )

        for key in base_keys & head_keys:
            base_comp = base_by_key[key]
            head_comp = head_by_key[key]
            if base_comp != head_comp:
                changed.append(
                    CBOMDiffItem(
                        name=head_comp.get("name", ""),
                        file=self._component_file(head_comp),
                        line=self._component_line(head_comp),
                        change_type=ChangeType.CHANGED,
                        details="properties changed",
                    )
                )

        unchanged_count = len(base_keys & head_keys) - len(changed)

        return CBOMDiff(
            base_scan_id=base_scan_id,
            head_scan_id=head_scan_id,
            added=added,
            removed=removed,
            changed=changed,
            unchanged_count=unchanged_count,
        )

    async def merge(
        self,
        scan_ids: list[uuid.UUID],
        session: AsyncSession,
    ) -> MergedCBOM:
        """Aggregate multiple CBOMs into one portfolio-level CBOM.

        Deduplicates components by (name, file, line).  When duplicates are
        found the component from the later scan takes precedence.
        """
        merged_components: dict[tuple[str, str, int], dict] = {}
        project_ids: set[uuid.UUID] = set()

        for scan_id in scan_ids:
            cbom_json = await self._load_cbom_json(scan_id, session)
            # Collect the project id from the scan
            stmt = select(Scan).where(Scan.id == scan_id)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            if scan is not None:
                project_ids.add(scan.project_id)

            for comp in cbom_json.get("components", []):
                key = self._component_key(comp)
                merged_components[key] = comp

        components = list(merged_components.values())
        return MergedCBOM(
            project_ids=sorted(project_ids),
            total_components=len(components),
            components=components,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _load_cbom_json(self, scan_id: uuid.UUID, session: AsyncSession) -> dict:
        """Load and return the CBOM JSON for a given scan, or raise 404."""
        stmt = select(Scan).where(Scan.id == scan_id).options(joinedload(Scan.cbom_document))
        result = await session.execute(stmt)
        scan = result.scalar_one_or_none()

        if scan is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

        cbom_doc: CBOMDocument | None = scan.cbom_document
        if cbom_doc is None:
            raise HTTPException(status_code=404, detail=f"CBOM not found for scan {scan_id}")

        return cbom_doc.cbom_json or {}

    @staticmethod
    def _component_key(comp: dict) -> tuple[str, str, int]:
        """Derive a deduplication key from a CycloneDX component dict."""
        name = comp.get("name", "")
        file = ""
        line = 0
        evidence = comp.get("evidence", {})
        if isinstance(evidence, dict):
            occurrences = evidence.get("occurrences", [])
            if occurrences and isinstance(occurrences, list):
                first = occurrences[0]
                file = first.get("location", "")
                line = first.get("line", 0)
        return (name, file, line)

    @staticmethod
    def _index_components(components: list[dict]) -> dict[tuple[str, str, int], dict]:
        """Build a dict mapping component keys to component dicts."""
        index: dict[tuple[str, str, int], dict] = {}
        for comp in components:
            key = CBOMService._component_key(comp)
            index[key] = comp
        return index

    @staticmethod
    def _component_file(comp: dict) -> str:
        """Extract file location from a CycloneDX component dict."""
        evidence = comp.get("evidence", {})
        if isinstance(evidence, dict):
            occurrences = evidence.get("occurrences", [])
            if occurrences and isinstance(occurrences, list):
                return occurrences[0].get("location", "")
        return ""

    @staticmethod
    def _component_line(comp: dict) -> int:
        """Extract line number from a CycloneDX component dict."""
        evidence = comp.get("evidence", {})
        if isinstance(evidence, dict):
            occurrences = evidence.get("occurrences", [])
            if occurrences and isinstance(occurrences, list):
                return occurrences[0].get("line", 0)
        return 0


# Module-level singleton for dependency injection
cbom_service = CBOMService()
