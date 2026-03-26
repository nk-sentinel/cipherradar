"""Jira integration config model (D18)."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class JiraConfig(Base):
    """Per-org Jira integration configuration (D18)."""

    __tablename__ = "jira_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    project_key: Mapped[str] = mapped_column(String(50), nullable=False)
    issue_type: Mapped[str] = mapped_column(String(100), server_default="Task", nullable=False)
    auth_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    field_mapping: Mapped[dict] = mapped_column(JSONB, server_default="{}", nullable=False)
    auto_create: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
    sync_status_back: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
