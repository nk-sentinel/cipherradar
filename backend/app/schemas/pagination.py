"""Reusable pagination schemas for all list endpoints (D11 standard pattern)."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import Field

from app.schemas.base import CamelCaseModel

T = TypeVar("T")


class PaginationParams(CamelCaseModel):
    """Query parameters for paginated list endpoints."""

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=25, ge=1, le=100)


class PaginatedResponse(CamelCaseModel, Generic[T]):
    """Standard paginated response envelope."""

    items: list[T]
    total: int
    page: int
    per_page: int
