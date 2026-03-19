from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.scan import Scan


class Finding(Base):
    """Individual cryptographic finding (ADR-012).

    High-cardinality filter columns (severity, quantum_status, asset_type)
    are top-level columns, not JSONB-only, for efficient indexing.
    Additional flexible metadata lives in the ``properties`` JSONB column
    with a GIN index.
    """

    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
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
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    quantum_status: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    location_file: Mapped[str] = mapped_column(String(2048), nullable=False)
    location_line: Mapped[int] = mapped_column(Integer, nullable=False)
    properties: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")
    project: Mapped[Project] = relationship("Project")

    from app.models.project import Project
    from app.models.scan import Scan
