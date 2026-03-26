"""LLM configuration model (D5)."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for SQLAlchemy Mapped[uuid.UUID]

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LLMConfig(Base):
    """Per-org LLM provider configuration (D5)."""

    __tablename__ = "llm_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    max_tokens: Mapped[int] = mapped_column(Integer, server_default="4096")
    temperature: Mapped[float] = mapped_column(Float, server_default="0.0")
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
