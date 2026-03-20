"""Tests for migration 004 — compliance_scores trending table."""

import importlib
import inspect
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import types

MIGRATION_MODULE = "app.db.migrations.versions.004_compliance_trending"


@pytest.fixture(scope="module")
def migration() -> "types.ModuleType":
    return importlib.import_module(MIGRATION_MODULE)


def _source(migration: "types.ModuleType") -> str:
    return inspect.getsource(migration)


def test_importable(migration: "types.ModuleType") -> None:
    assert migration is not None


def test_has_upgrade(migration: "types.ModuleType") -> None:
    assert hasattr(migration, "upgrade")
    assert callable(migration.upgrade)


def test_has_downgrade(migration: "types.ModuleType") -> None:
    assert hasattr(migration, "downgrade")
    assert callable(migration.downgrade)


def test_revision_identifiers(migration: "types.ModuleType") -> None:
    assert migration.revision == "004_compliance_trending"
    assert migration.down_revision == "003_rls_policies"


def test_compliance_scores_table(migration: "types.ModuleType") -> None:
    source = _source(migration)
    assert '"compliance_scores"' in source


def test_required_columns(migration: "types.ModuleType") -> None:
    source = _source(migration)
    for col in ("time", "org_id", "project_id", "framework", "score", "compliant_count", "non_compliant_count"):
        assert f'"{col}"' in source, f"Column {col!r} not found in migration"


def test_indexes_present(migration: "types.ModuleType") -> None:
    source = _source(migration)
    expected_indexes = [
        "ix_compliance_scores_time",
        "ix_compliance_scores_framework",
        "ix_compliance_scores_project_id",
        "ix_compliance_scores_org_id",
        "ix_compliance_scores_framework_project_time",
    ]
    for idx in expected_indexes:
        assert f'"{idx}"' in source, f"Index {idx!r} not found"


def test_timescaledb_comment(migration: "types.ModuleType") -> None:
    source = _source(migration)
    assert "hypertable" in source.lower()
    assert "TimescaleDB" in source


def test_downgrade_drops_table(migration: "types.ModuleType") -> None:
    downgrade_source = inspect.getsource(migration.downgrade)
    assert '"compliance_scores"' in downgrade_source


def test_downgrade_drops_indexes(migration: "types.ModuleType") -> None:
    downgrade_source = inspect.getsource(migration.downgrade)
    for idx in [
        "ix_compliance_scores_framework_project_time",
        "ix_compliance_scores_org_id",
        "ix_compliance_scores_project_id",
        "ix_compliance_scores_framework",
        "ix_compliance_scores_time",
    ]:
        assert f'"{idx}"' in downgrade_source, f"Index {idx!r} not dropped in downgrade"
