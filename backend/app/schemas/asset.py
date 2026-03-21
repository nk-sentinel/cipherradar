"""Schemas for crypto asset inventory endpoints."""

from app.schemas.base import CamelCaseModel


class AssetItem(CamelCaseModel):
    """A single cryptographic asset derived from a finding."""

    id: str
    name: str
    type: str
    language: str
    repo: str
    location: str
    quantum_status: str
    compliance: str


class AssetListResponse(CamelCaseModel):
    """Paginated list of crypto assets."""

    items: list[AssetItem]
    total: int
    page: int
    page_size: int
