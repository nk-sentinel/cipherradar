from __future__ import annotations

import enum
import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]
from datetime import datetime  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[datetime]
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.cbom import CBOMDocument
    from app.models.finding import Finding
    from app.models.project import Project


class ScanStatus(enum.StrEnum):
    """Possible states for a scan execution."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base):
    """A single scan execution (ADR-012)."""

    __tablename__ = "scans"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=ScanStatus.QUEUED,
    )
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped[Project] = relationship("Project", back_populates="scans")
    cbom_document: Mapped[CBOMDocument | None] = relationship(
        "CBOMDocument", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
