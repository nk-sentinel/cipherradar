from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class CBOMDocument(Base):
    """CBOM output per scan (ADR-012).

    The actual CBOM JSON is stored via the CBOMStore abstraction.
    For PostgresCBOMStore, the ``cbom_json`` column holds the document
    and ``storage_uri`` is ``postgres://<id>``.
    For S3CBOMStore, ``cbom_json`` is NULL and ``storage_uri`` points
    to the S3/MinIO object.
    """

    __tablename__ = "cbom_documents"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    storage_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    spec_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.7")
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # JSONB column used only by PostgresCBOMStore (dev/early stage)
    cbom_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship("Scan", back_populates="cbom_document")
