from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.project import Group
    from app.models.user import User


class Organisation(Base):
    """Top-level tenant (ADR-012)."""

    __tablename__ = "organisations"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="free")
    settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Phase 4.5 columns
    labels: Mapped[dict | None] = mapped_column(
        JSONB, server_default='{"group": "Group", "project": "Project"}'
    )
    default_schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    default_schedule_timezone: Mapped[str] = mapped_column(String(50), server_default="UTC")
    allow_project_schedule_override: Mapped[bool] = mapped_column(Boolean, server_default="true")
    risk_acceptance_enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    external_grc_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    deletion_policy: Mapped[str] = mapped_column(String(20), server_default="retain")
    audit_retention_days: Mapped[int] = mapped_column(Integer, server_default="730")
    audit_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    stale_scan_threshold_days: Mapped[int] = mapped_column(Integer, server_default="30")

    # Relationships
    groups: Mapped[list[Group]] = relationship("Group", back_populates="organisation", cascade="all, delete-orphan")
    users: Mapped[list[User]] = relationship("User", back_populates="organisation", cascade="all, delete-orphan")
