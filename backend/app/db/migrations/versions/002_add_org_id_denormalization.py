"""Add org_id to projects, scans, findings, cbom_documents for RLS.

This denormalization enables efficient PostgreSQL Row Level Security (RLS)
policies. Without it, RLS would need 3 joins per row check.

Revision ID: 002_add_org_id
Revises: 001_initial
Create Date: 2026-03-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "002_add_org_id"
down_revision: str | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- projects: add org_id ---
    op.add_column("projects", sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_projects_org_id", "projects", "organisations", ["org_id"], ["id"], ondelete="CASCADE")
    op.create_index("ix_projects_org_id", "projects", ["org_id"])

    # --- scans: add org_id ---
    op.add_column("scans", sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_scans_org_id", "scans", "organisations", ["org_id"], ["id"], ondelete="CASCADE")
    op.create_index("ix_scans_org_id", "scans", ["org_id"])

    # --- findings: add org_id ---
    op.add_column("findings", sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_findings_org_id", "findings", "organisations", ["org_id"], ["id"], ondelete="CASCADE")
    op.create_index("ix_findings_org_id", "findings", ["org_id"])

    # --- cbom_documents: add org_id ---
    op.add_column("cbom_documents", sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_cbom_documents_org_id", "cbom_documents", "organisations", ["org_id"], ["id"], ondelete="CASCADE"
    )
    op.create_index("ix_cbom_documents_org_id", "cbom_documents", ["org_id"])

    # Note: Backfill org_id from group hierarchy:
    # UPDATE projects SET org_id = groups.org_id FROM groups WHERE projects.group_id = groups.id;
    # UPDATE scans SET org_id = projects.org_id FROM projects WHERE scans.project_id = projects.id;
    # UPDATE findings SET org_id = scans.org_id FROM scans WHERE findings.scan_id = scans.id;
    # UPDATE cbom_documents SET org_id = scans.org_id FROM scans WHERE cbom_documents.scan_id = scans.id;
    # Then: ALTER TABLE projects ALTER COLUMN org_id SET NOT NULL;
    # (backfill as raw SQL since existing data may exist)


def downgrade() -> None:
    op.drop_index("ix_cbom_documents_org_id")
    op.drop_constraint("fk_cbom_documents_org_id", "cbom_documents")
    op.drop_column("cbom_documents", "org_id")

    op.drop_index("ix_findings_org_id")
    op.drop_constraint("fk_findings_org_id", "findings")
    op.drop_column("findings", "org_id")

    op.drop_index("ix_scans_org_id")
    op.drop_constraint("fk_scans_org_id", "scans")
    op.drop_column("scans", "org_id")

    op.drop_index("ix_projects_org_id")
    op.drop_constraint("fk_projects_org_id", "projects")
    op.drop_column("projects", "org_id")
