"""Environment stage model (D21)."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EnvironmentStage(Base):
    """Named deployment environment/stage for an organisation (D21)."""

    __tablename__ = "environment_stages"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    color: Mapped[str | None] = mapped_column(String(20), nullable=True)
    is_production: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
