"""Runtime observation model for OTel enrichment (ADR-028)."""

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]
from datetime import datetime  # noqa: TCH003 — required at runtime for Mapped[datetime]

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RuntimeObservation(Base):
    """A runtime TLS/cipher observation from an OTel Collector exporter."""

    __tablename__ = "runtime_observations"

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
    service_name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    tls_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(255), nullable=True)
    peer_cert_subject: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
