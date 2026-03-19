"""Unit tests for the initial Alembic migration.

These tests validate the migration module structure without requiring
a running database. They inspect the migration's operations to ensure
all expected tables, columns, indexes, and foreign keys are present.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import types

# Import the migration module directly.
MIGRATION_MODULE = "app.db.migrations.versions.001_initial_schema"


@pytest.fixture(scope="module")
def migration() -> types.ModuleType:
    """Import the migration module."""
    return importlib.import_module(MIGRATION_MODULE)


# --- Basic structure tests ---


def test_migration_importable(migration: types.ModuleType) -> None:
    """Migration module should import without errors."""
    assert migration is not None


def test_migration_has_upgrade(migration: types.ModuleType) -> None:
    """Migration must define an upgrade() function."""
    assert hasattr(migration, "upgrade")
    assert callable(migration.upgrade)


def test_migration_has_downgrade(migration: types.ModuleType) -> None:
    """Migration must define a downgrade() function."""
    assert hasattr(migration, "downgrade")
    assert callable(migration.downgrade)


def test_revision_identifiers(migration: types.ModuleType) -> None:
    """Migration must have correct revision identifiers."""
    assert migration.revision == "001_initial"
    assert migration.down_revision is None


# --- Table coverage tests ---

# Expected tables that must appear in the migration.
EXPECTED_TABLES = {
    "organisations",
    "groups",
    "projects",
    "scans",
    "cbom_documents",
    "findings",
    "users",
    "scan_metrics",
}


def _extract_source(migration: types.ModuleType) -> str:
    """Return the source code of the migration module."""
    import inspect

    return inspect.getsource(migration)


def test_all_tables_present_in_upgrade(migration: types.ModuleType) -> None:
    """Every expected table name should appear in a create_table call."""
    source = _extract_source(migration)
    for table_name in EXPECTED_TABLES:
        assert f'"{table_name}"' in source, f"Table {table_name!r} not found in migration source"


def test_all_tables_present_in_downgrade(migration: types.ModuleType) -> None:
    """Every expected table name should appear in a drop_table call in downgrade."""
    import inspect

    downgrade_source = inspect.getsource(migration.downgrade)
    for table_name in EXPECTED_TABLES:
        assert f'"{table_name}"' in downgrade_source, (
            f"Table {table_name!r} not found in downgrade(). "
            f"All tables created in upgrade() must be dropped in downgrade()."
        )


# --- Column type tests ---


def test_uuid_primary_keys(migration: types.ModuleType) -> None:
    """All main tables should use UUID primary keys."""
    source = _extract_source(migration)
    assert source.count("postgresql.UUID(as_uuid=True)") >= 8, (
        "Expected at least 8 UUID columns (id columns for all tables + FK references)"
    )


def test_jsonb_columns_present(migration: types.ModuleType) -> None:
    """JSONB columns should be defined for settings and properties."""
    source = _extract_source(migration)
    assert source.count("postgresql.JSONB") >= 4, (
        "Expected at least 4 JSONB column references "
        "(organisations.settings, projects.settings, cbom_documents.cbom_json, "
        "findings.properties)"
    )


def test_scan_status_enum_created(migration: types.ModuleType) -> None:
    """The scan_status PostgreSQL enum should be created in upgrade."""
    source = _extract_source(migration)
    assert "scan_status" in source
    assert '"queued"' in source
    assert '"running"' in source
    assert '"completed"' in source
    assert '"failed"' in source


# --- Foreign key tests ---


EXPECTED_FOREIGN_KEYS = [
    ("groups", "organisations.id"),
    ("groups", "groups.id"),
    ("projects", "groups.id"),
    ("scans", "projects.id"),
    ("cbom_documents", "scans.id"),
    ("findings", "scans.id"),
    ("findings", "projects.id"),
    ("users", "organisations.id"),
    ("scan_metrics", "projects.id"),
]


@pytest.mark.parametrize(("table", "fk_target"), EXPECTED_FOREIGN_KEYS)
def test_foreign_key_references(migration: types.ModuleType, table: str, fk_target: str) -> None:
    """Each expected foreign key target should appear in the migration source."""
    source = _extract_source(migration)
    assert f'ForeignKey("{fk_target}"' in source, f"Foreign key from {table!r} to {fk_target!r} not found in migration"


# --- Index tests ---


EXPECTED_INDEXES = [
    "ix_organisations_settings_gin",
    "ix_groups_org_id",
    "ix_groups_parent_group_id",
    "ix_projects_group_id",
    "ix_projects_settings_gin",
    "ix_scans_project_id",
    "ix_scans_status",
    "ix_cbom_documents_scan_id",
    "ix_findings_scan_id",
    "ix_findings_project_id",
    "ix_findings_rule_id",
    "ix_findings_severity",
    "ix_findings_quantum_status",
    "ix_findings_asset_type",
    "ix_findings_properties_gin",
    "ix_users_email",
    "ix_users_org_id",
    "ix_scan_metrics_project_id",
]


@pytest.mark.parametrize("index_name", EXPECTED_INDEXES)
def test_index_defined(migration: types.ModuleType, index_name: str) -> None:
    """Each expected index should be defined in the migration."""
    source = _extract_source(migration)
    assert f'"{index_name}"' in source, f"Index {index_name!r} not found in migration"


def test_gin_indexes_use_gin_method(migration: types.ModuleType) -> None:
    """GIN indexes must specify postgresql_using='gin'."""
    source = _extract_source(migration)
    gin_count = source.count('postgresql_using="gin"')
    assert gin_count >= 3, (
        f"Expected at least 3 GIN indexes (organisations.settings, projects.settings, "
        f"findings.properties), found {gin_count}"
    )


# --- TimescaleDB comment test ---


def test_timescaledb_hypertable_comment(migration: types.ModuleType) -> None:
    """Migration should contain a comment about creating the TimescaleDB hypertable."""
    source = _extract_source(migration)
    assert "create_hypertable" in source, "Migration should contain a comment about create_hypertable for scan_metrics"
    assert "TimescaleDB" in source, "Migration should mention TimescaleDB in a comment"


# --- Downgrade order test ---


def test_downgrade_drops_in_reverse_dependency_order(migration: types.ModuleType) -> None:
    """Downgrade must drop tables in reverse dependency order.

    Tables with foreign key dependents must be dropped before the tables they
    reference. The correct order (roughly): scan_metrics, users, findings,
    cbom_documents, scans, projects, groups, organisations.
    """
    import inspect

    downgrade_source = inspect.getsource(migration.downgrade)

    # Extract drop_table calls in order.
    import re

    drops = re.findall(r'op\.drop_table\("(\w+)"\)', downgrade_source)
    assert len(drops) == len(EXPECTED_TABLES), (
        f"Expected {len(EXPECTED_TABLES)} drop_table calls, found {len(drops)}: {drops}"
    )

    # Verify ordering constraints: child tables must be dropped before parent tables.
    def _pos(name: str) -> int:
        return drops.index(name)

    # findings depends on scans and projects
    assert _pos("findings") < _pos("scans")
    assert _pos("findings") < _pos("projects")

    # cbom_documents depends on scans
    assert _pos("cbom_documents") < _pos("scans")

    # scans depends on projects
    assert _pos("scans") < _pos("projects")

    # projects depends on groups
    assert _pos("projects") < _pos("groups")

    # groups depends on organisations
    assert _pos("groups") < _pos("organisations")

    # users depends on organisations
    assert _pos("users") < _pos("organisations")

    # scan_metrics depends on projects
    assert _pos("scan_metrics") < _pos("projects")
