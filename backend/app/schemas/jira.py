"""Pydantic schemas for Jira integration endpoints."""

from pydantic import Field

from app.schemas.base import CamelCaseModel


class JiraConnectRequest(CamelCaseModel):
    """Initiate Jira OAuth connection."""

    code: str = Field(min_length=1, description="OAuth authorisation code")


class JiraConnectResponse(CamelCaseModel):
    """Response after Jira OAuth connection."""

    connected: bool
    site_name: str = ""
    cloud_id: str = ""


class JiraStatusResponse(CamelCaseModel):
    """Jira integration status."""

    connected: bool
    site_name: str = ""
    cloud_id: str = ""


class JiraCallbackRequest(CamelCaseModel):
    """OAuth callback request."""

    code: str = Field(min_length=1)
    state: str = ""
