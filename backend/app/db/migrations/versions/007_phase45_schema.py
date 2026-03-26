"""Phase 4.5 schema additions for D1-D32 and ADR-034.

New columns on: organisations, users, projects, groups, scans, findings.
New tables: user_groups, api_keys, finding_status_history, finding_requests,
finding_comments, jira_configs, environment_stages, policy_overrides,
custom_rules, llm_configs, integration_tokens, artifact_registries, audit_logs.

Revision ID: 007_phase45_schema
Revises: 006_runtime_observations
Create Date: 2026-03-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "007_phase45_schema"
down_revision: str | None = "006_runtime_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # =========================================================================
    # 1. New columns on existing tables
    # =========================================================================

    # --- organisations ---
    op.add_column(
        "organisations",
        sa.Column("labels", postgresql.JSONB, server_default='{"group": "Group", "project": "Project"}'),
    )
    op.add_column(
        "organisations",
        sa.Column("default_schedule_cron", sa.String(100), nullable=True),
    )
    op.add_column(
        "organisations",
        sa.Column("default_schedule_timezone", sa.String(50), server_default="UTC"),
    )
    op.add_column(
        "organisations",
        sa.Column("allow_project_schedule_override", sa.Boolean, server_default="true"),
    )
    op.add_column(
        "organisations",
        sa.Column("risk_acceptance_enabled", sa.Boolean, server_default="true"),
    )
    op.add_column(
        "organisations",
        sa.Column("external_grc_url", sa.String(512), nullable=True),
    )
    op.add_column(
        "organisations",
        sa.Column("deletion_policy", sa.String(20), server_default="retain"),
    )
    op.add_column(
        "organisations",
        sa.Column("audit_retention_days", sa.Integer, server_default="730"),
    )
    op.add_column(
        "organisations",
        sa.Column("audit_webhook_url", sa.String(512), nullable=True),
    )
    op.add_column(
        "organisations",
        sa.Column("stale_scan_threshold_days", sa.Integer, server_default="30"),
    )

    # --- users ---
    op.add_column(
        "users",
        sa.Column("auth_source", sa.String(20), server_default="local", nullable=False),
    )
    op.add_column(
        "users",
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- projects ---
    op.add_column(
        "projects",
        sa.Column("type", sa.String(20), server_default="repository"),
    )
    op.add_column(
        "projects",
        sa.Column("linked_sources", postgresql.JSONB, server_default="[]"),
    )
    op.add_column(
        "projects",
        sa.Column("schedule_cron", sa.String(100), nullable=True),
    )
    op.add_column(
        "projects",
        sa.Column("schedule_timezone", sa.String(50), server_default="UTC"),
    )

    # --- groups ---
    op.add_column(
        "groups",
        sa.Column("schedule_cron", sa.String(100), nullable=True),
    )
    op.add_column(
        "groups",
        sa.Column("schedule_timezone", sa.String(50), server_default="UTC"),
    )

    # --- scans (D21 provenance) ---
    # Note: branch and commit_sha already exist from 001_initial_schema.
    # Widen commit_sha from 40 to 64 chars for future-proofing.
    op.alter_column("scans", "commit_sha", type_=sa.String(64), existing_type=sa.String(40))
    op.add_column("scans", sa.Column("tag", sa.String(255), nullable=True))
    op.add_column("scans", sa.Column("image_ref", sa.String(512), nullable=True))
    op.add_column("scans", sa.Column("image_digest", sa.String(128), nullable=True))
    op.add_column("scans", sa.Column("artifact_filename", sa.String(512), nullable=True))
    op.add_column("scans", sa.Column("artifact_checksum", sa.String(128), nullable=True))
    op.add_column("scans", sa.Column("environment", sa.String(50), nullable=True))
    op.add_column("scans", sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scans",
        sa.Column(
            "promoted_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )

    # --- findings (D14 status + ADR-034 fingerprint) ---
    op.add_column(
        "findings",
        sa.Column("status", sa.String(20), server_default="open", nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column(
            "assigned_to",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "findings",
        sa.Column("reopen_count", sa.Integer, server_default="0", nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column("last_reopened_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("fingerprint", sa.String(64), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("normalized_signature", sa.Text, nullable=True),
    )

    # =========================================================================
    # 2. Indexes on modified existing tables
    # =========================================================================
    op.create_index(
        "ix_findings_fingerprint",
        "findings",
        ["project_id", "fingerprint"],
    )
    op.create_index(
        "ix_findings_rule_file",
        "findings",
        ["project_id", "rule_id", "location_file"],
    )
    op.create_index(
        "ix_findings_status",
        "findings",
        ["project_id", "status"],
    )
    op.create_index(
        "ix_findings_assigned",
        "findings",
        ["assigned_to"],
        postgresql_where=sa.text("assigned_to IS NOT NULL"),
    )
    op.create_index("ix_scans_environment", "scans", ["environment"])

    # =========================================================================
    # 3. New junction table: user_groups (D12)
    # =========================================================================
    op.create_table(
        "user_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_user_groups_user_id", "user_groups", ["user_id"])
    op.create_index("ix_user_groups_group_id", "user_groups", ["group_id"])
    op.create_index("ix_user_groups_org_id", "user_groups", ["org_id"])
    op.create_index(
        "ix_user_groups_user_group_unique",
        "user_groups",
        ["user_id", "group_id"],
        unique=True,
    )

    # =========================================================================
    # 4. New tables
    # =========================================================================

    # --- api_keys (D7) ---
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("scopes", postgresql.JSONB, server_default="[]", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])

    # --- finding_status_history (D14) ---
    op.create_table(
        "finding_status_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "changed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("old_status", sa.String(20), nullable=True),
        sa.Column("new_status", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_finding_status_history_org_id", "finding_status_history", ["org_id"])
    op.create_index("ix_finding_status_history_finding_id", "finding_status_history", ["finding_id"])
    op.create_index("ix_finding_status_history_changed_by", "finding_status_history", ["changed_by"])
    op.create_index("ix_finding_status_history_created_at", "finding_status_history", ["created_at"])

    # --- finding_requests (D15 — risk acceptance / suppression requests) ---
    op.create_table(
        "finding_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "reviewed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("request_type", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("justification", sa.Text, nullable=False),
        sa.Column("review_note", sa.Text, nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_finding_requests_org_id", "finding_requests", ["org_id"])
    op.create_index("ix_finding_requests_finding_id", "finding_requests", ["finding_id"])
    op.create_index("ix_finding_requests_requested_by", "finding_requests", ["requested_by"])
    op.create_index("ix_finding_requests_status", "finding_requests", ["status"])

    # --- finding_comments (D14) ---
    op.create_table(
        "finding_comments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_finding_comments_org_id", "finding_comments", ["org_id"])
    op.create_index("ix_finding_comments_finding_id", "finding_comments", ["finding_id"])
    op.create_index("ix_finding_comments_user_id", "finding_comments", ["user_id"])

    # --- jira_configs (D18) ---
    op.create_table(
        "jira_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("project_key", sa.String(50), nullable=False),
        sa.Column("issue_type", sa.String(100), server_default="Task", nullable=False),
        sa.Column("auth_token_encrypted", sa.Text, nullable=False),
        sa.Column("field_mapping", postgresql.JSONB, server_default="{}", nullable=False),
        sa.Column("auto_create", sa.Boolean, server_default="false", nullable=False),
        sa.Column("sync_status_back", sa.Boolean, server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_jira_configs_org_id", "jira_configs", ["org_id"])

    # --- environment_stages (D21) ---
    op.create_table(
        "environment_stages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("display_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("color", sa.String(20), nullable=True),
        sa.Column("is_production", sa.Boolean, server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_environment_stages_org_id", "environment_stages", ["org_id"])
    op.create_index(
        "ix_environment_stages_org_name_unique",
        "environment_stages",
        ["org_id", "name"],
        unique=True,
    )

    # --- policy_overrides (D26) ---
    op.create_table(
        "policy_overrides",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("framework", sa.String(100), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_policy_overrides_org_id", "policy_overrides", ["org_id"])
    op.create_index("ix_policy_overrides_project_id", "policy_overrides", ["project_id"])
    op.create_index("ix_policy_overrides_group_id", "policy_overrides", ["group_id"])
    op.create_index(
        "ix_policy_overrides_framework_rule",
        "policy_overrides",
        ["org_id", "framework", "rule_id"],
    )

    # --- custom_rules (D27) ---
    op.create_table(
        "custom_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("language", sa.String(50), nullable=False),
        sa.Column("pattern_type", sa.String(30), nullable=False),
        sa.Column("pattern", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), server_default="medium", nullable=False),
        sa.Column("enabled", sa.Boolean, server_default="true", nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_custom_rules_org_id", "custom_rules", ["org_id"])
    op.create_index("ix_custom_rules_language", "custom_rules", ["language"])
    op.create_index("ix_custom_rules_enabled", "custom_rules", ["org_id", "enabled"])

    # --- llm_configs (D5) ---
    op.create_table(
        "llm_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("api_key_encrypted", sa.Text, nullable=False),
        sa.Column("endpoint_url", sa.String(512), nullable=True),
        sa.Column("max_tokens", sa.Integer, server_default="4096"),
        sa.Column("temperature", sa.Float, server_default="0.0"),
        sa.Column("enabled", sa.Boolean, server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_llm_configs_org_id", "llm_configs", ["org_id"])

    # --- integration_tokens (D3 — git provider tokens) ---
    op.create_table(
        "integration_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("token_encrypted", sa.Text, nullable=False),
        sa.Column("scope", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_integration_tokens_org_id", "integration_tokens", ["org_id"])
    op.create_index("ix_integration_tokens_user_id", "integration_tokens", ["user_id"])
    op.create_index("ix_integration_tokens_provider", "integration_tokens", ["org_id", "provider"])

    # --- artifact_registries (D2) ---
    op.create_table(
        "artifact_registries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("registry_type", sa.String(50), nullable=False),
        sa.Column("url", sa.String(512), nullable=False),
        sa.Column("auth_token_encrypted", sa.Text, nullable=True),
        sa.Column("enabled", sa.Boolean, server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_artifact_registries_org_id", "artifact_registries", ["org_id"])

    # --- audit_logs (D30 — comprehensive audit trail) ---
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action_type", "audit_logs", ["action_type"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"])
    op.create_index("ix_audit_logs_details_gin", "audit_logs", ["details"], postgresql_using="gin")

    # =========================================================================
    # 5. RLS on new tables
    # =========================================================================
    new_tenant_tables = [
        "user_groups",
        "api_keys",
        "finding_status_history",
        "finding_requests",
        "finding_comments",
        "jira_configs",
        "environment_stages",
        "policy_overrides",
        "custom_rules",
        "llm_configs",
        "integration_tokens",
        "artifact_registries",
        "audit_logs",
    ]
    for table in new_tenant_tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} "
            f"USING (org_id = current_setting('app.current_org_id')::uuid)"
        )


def downgrade() -> None:
    # =========================================================================
    # Reverse order: RLS policies, tables, indexes, columns
    # =========================================================================

    new_tenant_tables = [
        "audit_logs",
        "artifact_registries",
        "integration_tokens",
        "llm_configs",
        "custom_rules",
        "policy_overrides",
        "environment_stages",
        "jira_configs",
        "finding_comments",
        "finding_requests",
        "finding_status_history",
        "api_keys",
        "user_groups",
    ]

    # Drop RLS policies
    for table in new_tenant_tables:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    # Drop new tables (reverse creation order)
    op.drop_table("audit_logs")
    op.drop_table("artifact_registries")
    op.drop_table("integration_tokens")
    op.drop_table("llm_configs")
    op.drop_table("custom_rules")
    op.drop_table("policy_overrides")
    op.drop_table("environment_stages")
    op.drop_table("jira_configs")
    op.drop_table("finding_comments")
    op.drop_table("finding_requests")
    op.drop_table("finding_status_history")
    op.drop_table("api_keys")
    op.drop_table("user_groups")

    # Drop new indexes on existing tables
    op.drop_index("ix_scans_environment")
    op.drop_index("ix_findings_assigned")
    op.drop_index("ix_findings_status")
    op.drop_index("ix_findings_rule_file")
    op.drop_index("ix_findings_fingerprint")

    # Drop new columns on findings
    op.drop_column("findings", "normalized_signature")
    op.drop_column("findings", "fingerprint")
    op.drop_column("findings", "last_reopened_at")
    op.drop_column("findings", "reopen_count")
    op.drop_column("findings", "assigned_to")
    op.drop_column("findings", "status")

    # Drop new columns on scans
    op.drop_column("scans", "promoted_by")
    op.drop_column("scans", "promoted_at")
    op.drop_column("scans", "environment")
    op.drop_column("scans", "artifact_checksum")
    op.drop_column("scans", "artifact_filename")
    op.drop_column("scans", "image_digest")
    op.drop_column("scans", "image_ref")
    op.drop_column("scans", "tag")
    # Revert commit_sha width
    op.alter_column("scans", "commit_sha", type_=sa.String(40), existing_type=sa.String(64))

    # Drop new columns on groups
    op.drop_column("groups", "schedule_timezone")
    op.drop_column("groups", "schedule_cron")

    # Drop new columns on projects
    op.drop_column("projects", "schedule_timezone")
    op.drop_column("projects", "schedule_cron")
    op.drop_column("projects", "linked_sources")
    op.drop_column("projects", "type")

    # Drop new columns on users
    op.drop_column("users", "deleted_at")
    op.drop_column("users", "disabled_at")
    op.drop_column("users", "last_active_at")
    op.drop_column("users", "auth_source")

    # Drop new columns on organisations
    op.drop_column("organisations", "stale_scan_threshold_days")
    op.drop_column("organisations", "audit_webhook_url")
    op.drop_column("organisations", "audit_retention_days")
    op.drop_column("organisations", "deletion_policy")
    op.drop_column("organisations", "external_grc_url")
    op.drop_column("organisations", "risk_acceptance_enabled")
    op.drop_column("organisations", "allow_project_schedule_override")
    op.drop_column("organisations", "default_schedule_timezone")
    op.drop_column("organisations", "default_schedule_cron")
    op.drop_column("organisations", "labels")
