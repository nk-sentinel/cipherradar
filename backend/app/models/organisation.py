from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
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

    # Relationships
    groups: Mapped[list[Group]] = relationship("Group", back_populates="organisation", cascade="all, delete-orphan")
    users: Mapped[list[User]] = relationship("User", back_populates="organisation", cascade="all, delete-orphan")
