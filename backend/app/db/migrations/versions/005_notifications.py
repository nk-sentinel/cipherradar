"""Create notifications and notification_preferences tables.

Revision ID: 005_notifications
Revises: 004_compliance_trending
Create Date: 2026-03-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "005_notifications"
down_revision: str | None = "004_compliance_trending"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- notifications table ------------------------------------------------
    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("trigger_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("link", sa.String(2048), nullable=True),
        sa.Column("read", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])
    op.create_index("ix_notifications_org_id", "notifications", ["org_id"])
    op.create_index("ix_notifications_trigger_type", "notifications", ["trigger_type"])
    op.create_index("ix_notifications_severity", "notifications", ["severity"])
    op.create_index("ix_notifications_user_read", "notifications", ["user_id", "read"])
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])

    # -- notification_preferences table -------------------------------------
    op.create_table(
        "notification_preferences",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("trigger_type", sa.String(100), nullable=False),
        sa.Column("in_app", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("email", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("teams", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_index("ix_notification_preferences_user_id", "notification_preferences", ["user_id"])
    op.create_index(
        "ix_notification_preferences_user_trigger",
        "notification_preferences",
        ["user_id", "trigger_type"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_notification_preferences_user_trigger")
    op.drop_index("ix_notification_preferences_user_id")
    op.drop_table("notification_preferences")

    op.drop_index("ix_notifications_created_at")
    op.drop_index("ix_notifications_user_read")
    op.drop_index("ix_notifications_severity")
    op.drop_index("ix_notifications_trigger_type")
    op.drop_index("ix_notifications_org_id")
    op.drop_index("ix_notifications_user_id")
    op.drop_table("notifications")
