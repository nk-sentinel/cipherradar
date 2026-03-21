"""Create runtime_observations table for OTel enrichment (ADR-028).

Revision ID: 006_runtime_observations
Revises: 005_notifications
Create Date: 2026-03-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "006_runtime_observations"
down_revision: str | None = "005_notifications"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "runtime_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("service_name", sa.String(512), nullable=False),
        sa.Column("tls_version", sa.String(20), nullable=True),
        sa.Column("cipher_suite", sa.String(255), nullable=True),
        sa.Column("peer_cert_subject", sa.String(2048), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_index("ix_runtime_observations_project_id", "runtime_observations", ["project_id"])
    op.create_index("ix_runtime_observations_org_id", "runtime_observations", ["org_id"])
    op.create_index("ix_runtime_observations_service_name", "runtime_observations", ["service_name"])
    op.create_index("ix_runtime_observations_observed_at", "runtime_observations", ["observed_at"])
    op.create_index(
        "ix_runtime_observations_project_service",
        "runtime_observations",
        ["project_id", "service_name"],
    )


def downgrade() -> None:
    op.drop_index("ix_runtime_observations_project_service")
    op.drop_index("ix_runtime_observations_observed_at")
    op.drop_index("ix_runtime_observations_service_name")
    op.drop_index("ix_runtime_observations_org_id")
    op.drop_index("ix_runtime_observations_project_id")
    op.drop_table("runtime_observations")
