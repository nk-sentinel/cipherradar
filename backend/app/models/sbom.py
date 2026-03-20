from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SBOMDocument(Base):
    """SBOM document stored via CBOMStore pattern.

    The SBOM JSON is stored either inline (JSONB column for dev) or
    externally (S3/MinIO for production), following the same pattern
    as CBOMDocument.
    """

    __tablename__ = "sbom_documents"

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
    storage_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    spec_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    components_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # JSONB column for inline storage (dev/early stage)
    sbom_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
