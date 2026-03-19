"""initial schema — all tables from ADR-012

Revision ID: 001_initial
Revises:
Create Date: 2026-03-19

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- organisations ---
    op.create_table(
        "organisations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("plan", sa.String(50), nullable=False, server_default="free"),
        sa.Column("settings", postgresql.JSONB, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_organisations_settings_gin", "organisations", ["settings"], postgresql_using="gin")

    # --- groups ---
    op.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "parent_group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_groups_org_id", "groups", ["org_id"])
    op.create_index("ix_groups_parent_group_id", "groups", ["parent_group_id"])

    # --- projects ---
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("git_url", sa.String(2048), nullable=True),
        sa.Column("provider", sa.String(50), nullable=True),
        sa.Column("settings", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_projects_group_id", "projects", ["group_id"])
    op.create_index("ix_projects_settings_gin", "projects", ["settings"], postgresql_using="gin")

    # --- scans ---
    scan_status_enum = postgresql.ENUM(
        "queued", "running", "completed", "failed", name="scan_status", create_type=False
    )
    scan_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", scan_status_enum, nullable=False, server_default="queued"),
        sa.Column("branch", sa.String(255), nullable=True),
        sa.Column("commit_sha", sa.String(40), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    # --- cbom_documents ---
    op.create_table(
        "cbom_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("storage_uri", sa.String(2048), nullable=False),
        sa.Column("spec_version", sa.String(20), nullable=False, server_default="1.7"),
        sa.Column("serial_number", sa.String(255), nullable=True),
        sa.Column("cbom_json", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_cbom_documents_scan_id", "cbom_documents", ["scan_id"], unique=True)

    # --- findings ---
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("quantum_status", sa.String(50), nullable=False),
        sa.Column("asset_type", sa.String(100), nullable=False),
        sa.Column("location_file", sa.String(2048), nullable=False),
        sa.Column("location_line", sa.Integer, nullable=False),
        sa.Column("properties", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_project_id", "findings", ["project_id"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_quantum_status", "findings", ["quantum_status"])
    op.create_index("ix_findings_asset_type", "findings", ["asset_type"])
    op.create_index("ix_findings_properties_gin", "findings", ["properties"], postgresql_using="gin")

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="developer"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_org_id", "users", ["org_id"])

    # --- scan_metrics (TimescaleDB hypertable candidate) ---
    #
    # NOTE: After running this migration, if TimescaleDB is installed, execute:
    #
    #   CREATE EXTENSION IF NOT EXISTS timescaledb;
    #   SELECT create_hypertable('scan_metrics', 'time');
    #
    # Do NOT call create_hypertable inside the migration — it will fail if
    # the TimescaleDB extension is not available.
    op.create_table(
        "scan_metrics",
        sa.Column("time", sa.DateTime(timezone=True), nullable=False, primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
            primary_key=True,
        ),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("quantum_risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("compliance_score", sa.Float, nullable=False, server_default="0.0"),
    )
    op.create_index("ix_scan_metrics_project_id", "scan_metrics", ["project_id"])


def downgrade() -> None:
    # Drop tables in reverse dependency order.
    op.drop_table("scan_metrics")
    op.drop_table("users")
    op.drop_table("findings")
    op.drop_table("cbom_documents")
    op.drop_table("scans")

    # Drop the scan_status enum type after the scans table is gone.
    postgresql.ENUM(name="scan_status").drop(op.get_bind(), checkfirst=True)

    op.drop_table("projects")
    op.drop_table("groups")
    op.drop_table("organisations")
