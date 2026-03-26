from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.organisation import Organisation
    from app.models.scan import Scan


class Group(Base):
    """Hierarchical grouping within an organisation (ADR-012)."""

    __tablename__ = "groups"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("groups.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Phase 4.5 columns
    schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    schedule_timezone: Mapped[str] = mapped_column(String(50), server_default="UTC")

    # Relationships
    organisation: Mapped[Organisation] = relationship("Organisation", back_populates="groups")
    parent_group: Mapped[Group | None] = relationship("Group", remote_side="Group.id", back_populates="children")
    children: Mapped[list[Group]] = relationship("Group", back_populates="parent_group")
    projects: Mapped[list[Project]] = relationship("Project", back_populates="group", cascade="all, delete-orphan")


class Project(Base):
    """A scannable codebase (ADR-012)."""

    __tablename__ = "projects"

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    git_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    settings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Phase 4.5 columns
    type: Mapped[str] = mapped_column(String(20), server_default="repository")
    linked_sources: Mapped[dict | None] = mapped_column(JSONB, server_default="[]")
    schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    schedule_timezone: Mapped[str] = mapped_column(String(50), server_default="UTC")

    # Relationships
    group: Mapped[Group] = relationship("Group", back_populates="projects")
    scans: Mapped[list[Scan]] = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

    from app.models.organisation import Organisation
    from app.models.scan import Scan
