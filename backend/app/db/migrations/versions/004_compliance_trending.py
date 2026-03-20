"""Create compliance_scores table for compliance trending.

This table stores periodic compliance score snapshots per project/framework.
It is designed as a TimescaleDB hypertable keyed on the ``time`` column.

After running this migration, execute manually on the database:
    SELECT create_hypertable('compliance_scores', 'time');

Revision ID: 004_compliance_trending
Revises: 003_rls_policies
Create Date: 2026-03-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "004_compliance_trending"
down_revision: str | None = "003_rls_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "compliance_scores",
        sa.Column("time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("framework", sa.String(100), nullable=False),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column("compliant_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("non_compliant_count", sa.Integer, nullable=False, server_default="0"),
    )

    # Indexes for common query patterns
    op.create_index(
        "ix_compliance_scores_time",
        "compliance_scores",
        ["time"],
    )
    op.create_index(
        "ix_compliance_scores_framework",
        "compliance_scores",
        ["framework"],
    )
    op.create_index(
        "ix_compliance_scores_project_id",
        "compliance_scores",
        ["project_id"],
    )
    op.create_index(
        "ix_compliance_scores_org_id",
        "compliance_scores",
        ["org_id"],
    )
    op.create_index(
        "ix_compliance_scores_framework_project_time",
        "compliance_scores",
        ["framework", "project_id", "time"],
    )

    # Note: After running this migration, create the TimescaleDB hypertable:
    #   SELECT create_hypertable('compliance_scores', 'time');
    # This must be done manually as TimescaleDB may not be installed in all
    # environments (dev, CI). The table works as a regular PostgreSQL table
    # without TimescaleDB, just without automatic chunk management.


def downgrade() -> None:
    op.drop_index("ix_compliance_scores_framework_project_time")
    op.drop_index("ix_compliance_scores_org_id")
    op.drop_index("ix_compliance_scores_project_id")
    op.drop_index("ix_compliance_scores_framework")
    op.drop_index("ix_compliance_scores_time")
    op.drop_table("compliance_scores")
