from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    import uuid

    from app.models.organisation import Organisation


class User(Base):
    """User model for authentication (ADR-013).

    Supports JWT + refresh token for human users. Password is hashed
    with bcrypt via passlib.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="developer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Relationships
    organisation: Mapped[Organisation] = relationship("Organisation", back_populates="users")
