"""Tests for CBOMService: diff, merge, and versioning logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.scan import ScanStatus
from app.services.cbom_service import CBOMService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_component(name: str, file: str = "main.py", line: int = 10, **extra: object) -> dict:
    """Build a minimal CycloneDX component dict with evidence."""
    comp: dict = {
        "name": name,
        "type": "crypto-asset",
        "evidence": {
            "occurrences": [{"location": file, "line": line}],
        },
    }
    comp.update(extra)
    return comp


def _make_scan_with_cbom(
    scan_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    components: list[dict] | None = None,
    completed_at: datetime | None = None,
    findings_count: int = 0,
) -> MagicMock:
    """Build a mock Scan + CBOMDocument pair."""
    scan = MagicMock()
    scan.id = scan_id or uuid.uuid4()
    scan.project_id = project_id or uuid.uuid4()
    scan.status = ScanStatus.COMPLETED.value
    scan.findings_count = findings_count
    scan.completed_at = completed_at or datetime.now(UTC)
    scan.created_at = scan.completed_at

    cbom_doc = MagicMock()
    cbom_doc.spec_version = "1.7"
    cbom_doc.cbom_json = {
        "specVersion": "1.7",
        "components": components or [],
    }
    scan.cbom_document = cbom_doc
    return scan


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diff_detects_added_components() -> None:
    """Components in head but not in base should appear as 'added'."""
    service = CBOMService()
    base_scan_id = uuid.uuid4()
    head_scan_id = uuid.uuid4()

    base_scan = _make_scan_with_cbom(scan_id=base_scan_id, components=[])
    head_scan = _make_scan_with_cbom(
        scan_id=head_scan_id,
        components=[_make_component("AES-256-GCM")],
    )

    session = AsyncMock()

    # _load_cbom_json calls session.execute twice (once per scan_id)
    base_result = MagicMock()
    base_result.scalar_one_or_none.return_value = base_scan
    head_result = MagicMock()
    head_result.scalar_one_or_none.return_value = head_scan

    session.execute = AsyncMock(side_effect=[base_result, head_result])

    result = await service.diff(base_scan_id, head_scan_id, session)

    assert len(result.added) == 1
    assert result.added[0].name == "AES-256-GCM"
    assert result.added[0].change_type == "added"
    assert len(result.removed) == 0
    assert len(result.changed) == 0
    assert result.unchanged_count == 0


@pytest.mark.asyncio
async def test_diff_detects_removed_components() -> None:
    """Components in base but not in head should appear as 'removed'."""
    service = CBOMService()
    base_scan_id = uuid.uuid4()
    head_scan_id = uuid.uuid4()

    base_scan = _make_scan_with_cbom(
        scan_id=base_scan_id,
        components=[_make_component("RSA-2048", file="crypto.py", line=5)],
    )
    head_scan = _make_scan_with_cbom(scan_id=head_scan_id, components=[])

    session = AsyncMock()
    base_result = MagicMock()
    base_result.scalar_one_or_none.return_value = base_scan
    head_result = MagicMock()
    head_result.scalar_one_or_none.return_value = head_scan

    session.execute = AsyncMock(side_effect=[base_result, head_result])

    result = await service.diff(base_scan_id, head_scan_id, session)

    assert len(result.removed) == 1
    assert result.removed[0].name == "RSA-2048"
    assert result.removed[0].file == "crypto.py"
    assert result.removed[0].change_type == "removed"
    assert len(result.added) == 0
    assert len(result.changed) == 0


@pytest.mark.asyncio
async def test_diff_detects_changed_components() -> None:
    """Components with same key but different properties should be 'changed'."""
    service = CBOMService()
    base_scan_id = uuid.uuid4()
    head_scan_id = uuid.uuid4()

    base_comp = _make_component("AES-256-GCM", file="enc.py", line=20)
    base_comp["cryptoProperties"] = {"keyLength": 128}

    head_comp = _make_component("AES-256-GCM", file="enc.py", line=20)
    head_comp["cryptoProperties"] = {"keyLength": 256}

    base_scan = _make_scan_with_cbom(scan_id=base_scan_id, components=[base_comp])
    head_scan = _make_scan_with_cbom(scan_id=head_scan_id, components=[head_comp])

    session = AsyncMock()
    base_result = MagicMock()
    base_result.scalar_one_or_none.return_value = base_scan
    head_result = MagicMock()
    head_result.scalar_one_or_none.return_value = head_scan

    session.execute = AsyncMock(side_effect=[base_result, head_result])

    result = await service.diff(base_scan_id, head_scan_id, session)

    assert len(result.changed) == 1
    assert result.changed[0].name == "AES-256-GCM"
    assert result.changed[0].change_type == "changed"
    assert result.unchanged_count == 0


@pytest.mark.asyncio
async def test_diff_identical_cboms_zero_changes() -> None:
    """Identical CBOMs should yield zero added/removed/changed."""
    service = CBOMService()
    base_scan_id = uuid.uuid4()
    head_scan_id = uuid.uuid4()

    comp = _make_component("SHA-256", file="hash.py", line=8)
    base_scan = _make_scan_with_cbom(scan_id=base_scan_id, components=[comp])
    head_scan = _make_scan_with_cbom(scan_id=head_scan_id, components=[comp])

    session = AsyncMock()
    base_result = MagicMock()
    base_result.scalar_one_or_none.return_value = base_scan
    head_result = MagicMock()
    head_result.scalar_one_or_none.return_value = head_scan

    session.execute = AsyncMock(side_effect=[base_result, head_result])

    result = await service.diff(base_scan_id, head_scan_id, session)

    assert len(result.added) == 0
    assert len(result.removed) == 0
    assert len(result.changed) == 0
    assert result.unchanged_count == 1


# ---------------------------------------------------------------------------
# Merge tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_merge_aggregates_components() -> None:
    """Merge should combine components from multiple scans."""
    service = CBOMService()
    scan_id_1 = uuid.uuid4()
    scan_id_2 = uuid.uuid4()
    project_id = uuid.uuid4()

    scan1 = _make_scan_with_cbom(
        scan_id=scan_id_1,
        project_id=project_id,
        components=[_make_component("AES-256-GCM", file="a.py", line=1)],
    )
    scan2 = _make_scan_with_cbom(
        scan_id=scan_id_2,
        project_id=project_id,
        components=[_make_component("RSA-2048", file="b.py", line=5)],
    )

    session = AsyncMock()

    # For merge, _load_cbom_json is called once per scan, then an extra
    # select(Scan) for each scan_id to get project_id.  That means 4 calls.
    cbom_result_1 = MagicMock()
    cbom_result_1.scalar_one_or_none.return_value = scan1
    project_result_1 = MagicMock()
    project_result_1.scalar_one_or_none.return_value = scan1

    cbom_result_2 = MagicMock()
    cbom_result_2.scalar_one_or_none.return_value = scan2
    project_result_2 = MagicMock()
    project_result_2.scalar_one_or_none.return_value = scan2

    session.execute = AsyncMock(side_effect=[cbom_result_1, project_result_1, cbom_result_2, project_result_2])

    result = await service.merge([scan_id_1, scan_id_2], session)

    assert result.total_components == 2
    assert len(result.components) == 2
    names = {c["name"] for c in result.components}
    assert names == {"AES-256-GCM", "RSA-2048"}


@pytest.mark.asyncio
async def test_merge_deduplicates_components() -> None:
    """Merge should deduplicate components with the same (name, file, line)."""
    service = CBOMService()
    scan_id_1 = uuid.uuid4()
    scan_id_2 = uuid.uuid4()
    project_id = uuid.uuid4()

    shared_comp = _make_component("AES-256-GCM", file="enc.py", line=10)

    scan1 = _make_scan_with_cbom(
        scan_id=scan_id_1,
        project_id=project_id,
        components=[shared_comp],
    )
    scan2 = _make_scan_with_cbom(
        scan_id=scan_id_2,
        project_id=project_id,
        components=[shared_comp],
    )

    session = AsyncMock()

    cbom_result_1 = MagicMock()
    cbom_result_1.scalar_one_or_none.return_value = scan1
    project_result_1 = MagicMock()
    project_result_1.scalar_one_or_none.return_value = scan1

    cbom_result_2 = MagicMock()
    cbom_result_2.scalar_one_or_none.return_value = scan2
    project_result_2 = MagicMock()
    project_result_2.scalar_one_or_none.return_value = scan2

    session.execute = AsyncMock(side_effect=[cbom_result_1, project_result_1, cbom_result_2, project_result_2])

    result = await service.merge([scan_id_1, scan_id_2], session)

    assert result.total_components == 1
    assert result.components[0]["name"] == "AES-256-GCM"


# ---------------------------------------------------------------------------
# Versioning tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_versioning_increments() -> None:
    """Version numbers should be assigned in chronological order."""
    service = CBOMService()
    project_id = uuid.uuid4()

    scan1 = _make_scan_with_cbom(
        project_id=project_id,
        completed_at=datetime(2025, 1, 1, tzinfo=UTC),
        findings_count=3,
    )
    scan2 = _make_scan_with_cbom(
        project_id=project_id,
        completed_at=datetime(2025, 2, 1, tzinfo=UTC),
        findings_count=5,
    )

    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.unique.return_value = mock_result
    mock_result.scalars.return_value = mock_result
    mock_result.all.return_value = [scan1, scan2]
    session.execute = AsyncMock(return_value=mock_result)

    versions = await service.get_versions(project_id, session)

    assert len(versions) == 2
    assert versions[0].version_number == 1
    assert versions[0].findings_count == 3
    assert versions[1].version_number == 2
    assert versions[1].findings_count == 5
