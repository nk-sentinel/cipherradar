"""Schemas for user organisation membership endpoints."""

from app.schemas.base import CamelCaseModel


class UserOrg(CamelCaseModel):
    """An organisation the current user belongs to."""

    id: str
    name: str
    plan: str
    role: str


class UserOrgList(CamelCaseModel):
    """Response for listing user's organisations."""

    items: list[UserOrg]
