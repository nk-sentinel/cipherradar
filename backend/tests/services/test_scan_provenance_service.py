"""Tests for scan provenance and environment promotion service (D21)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.scan import Scan
from app.services.scan_provenance_service import ScanProvenanceService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scan(
    *,
    environment: str | None = "dev",
    project_id: uuid.UUID | None = None,
) -> MagicMock:
    s = MagicMock(spec=Scan)
    s.id = uuid.uuid4()
    s.project_id = project_id or uuid.uuid4()
    s.org_id = uuid.uuid4()
    s.branch = "main"
    s.commit_sha = "abc123"
    s.tag = "v1.0.0"
    s.image_ref = "ghcr.io/org/app:v1"
    s.image_digest = "sha256:abc"
    s.artifact_filename = "app.tar.gz"
    s.artifact_checksum = "sha256:def"
    s.environment = environment
    s.promoted_at = None
    s.promoted_by = None
    s.created_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
    s.findings_count = 5
    s.status = "completed"
    return s


def _make_actor(*, org_id: uuid.UUID | None = None) -> MagicMock:
    actor = MagicMock()
    actor.user_id = str(uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = "security_engineer"
    return actor


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

service = ScanProvenanceService()


@pytest.mark.asyncio
async def test_provenance_fields() -> None:
    """get_provenance returns all expected provenance fields."""
    scan = _make_scan()
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = scan
    session.execute = AsyncMock(return_value=result_mock)

    result = await service.get_provenance(scan.id, session)

    assert result.scan_id == scan.id
    assert result.branch == "main"
    assert result.commit_sha == "abc123"
    assert result.tag == "v1.0.0"
    assert result.image_ref == "ghcr.io/org/app:v1"
    assert result.image_digest == "sha256:abc"
    assert result.artifact_filename == "app.tar.gz"
    assert result.artifact_checksum == "sha256:def"
    assert result.environment == "dev"


@pytest.mark.asyncio
async def test_provenance_not_found() -> None:
    """get_provenance raises 404 for unknown scan."""
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result_mock)

    with pytest.raises(HTTPException) as exc_info:
        await service.get_provenance(uuid.uuid4(), session)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_promote_transfers_tag() -> None:
    """promote updates the scan's environment to the target."""
    project_id = uuid.uuid4()
    scan = _make_scan(environment="dev", project_id=project_id)
    actor = _make_actor()

    session = AsyncMock()
    # First execute: load scan
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    # Second execute: find existing scans in target env
    existing_result = MagicMock()
    existing_result.scalars.return_value.all.return_value = []

    session.execute = AsyncMock(side_effect=[scan_result, existing_result])

    with patch.object(service, "_ScanProvenanceService__audit", new=AsyncMock(), create=True):
        result = await service.promote(scan.id, "dev", "staging", actor, session)

    assert scan.environment == "staging"
    assert scan.promoted_at is not None
    assert result.environment == "staging"


@pytest.mark.asyncio
async def test_promote_demotes_previous() -> None:
    """promote clears environment from any existing scan in the target env."""
    project_id = uuid.uuid4()
    scan = _make_scan(environment="dev", project_id=project_id)
    old_scan = _make_scan(environment="staging", project_id=project_id)
    actor = _make_actor()

    session = AsyncMock()
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    existing_result = MagicMock()
    existing_result.scalars.return_value.all.return_value = [old_scan]

    session.execute = AsyncMock(side_effect=[scan_result, existing_result])

    result = await service.promote(scan.id, "dev", "staging", actor, session)

    # Old scan should be demoted
    assert old_scan.environment is None
    assert old_scan.promoted_at is None
    assert old_scan.promoted_by is None
    # New scan promoted
    assert scan.environment == "staging"


@pytest.mark.asyncio
async def test_promote_wrong_env_raises() -> None:
    """promote raises 400 when scan is not in the expected from_env."""
    scan = _make_scan(environment="staging")
    actor = _make_actor()

    session = AsyncMock()
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    session.execute = AsyncMock(return_value=scan_result)

    with pytest.raises(HTTPException) as exc_info:
        await service.promote(scan.id, "dev", "staging", actor, session)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_environment_crud() -> None:
    """get_environments returns stages ordered by display_order."""
    from app.models.environment_stage import EnvironmentStage

    stage1 = MagicMock(spec=EnvironmentStage)
    stage1.id = uuid.uuid4()
    stage1.name = "dev"
    stage1.display_order = 0
    stage1.color = "#22c55e"
    stage1.is_production = False
    stage1.org_id = uuid.uuid4()
    stage1.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stage1.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    stage2 = MagicMock(spec=EnvironmentStage)
    stage2.id = uuid.uuid4()
    stage2.name = "prod"
    stage2.display_order = 2
    stage2.color = "#ef4444"
    stage2.is_production = True
    stage2.org_id = stage1.org_id
    stage2.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stage2.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalars.return_value.all.return_value = [stage1, stage2]
    session.execute = AsyncMock(return_value=result_mock)

    result = await service.get_environments(stage1.org_id, session)

    assert len(result) == 2
    assert result[0].name == "dev"
    assert result[1].name == "prod"
    assert result[1].is_production is True
