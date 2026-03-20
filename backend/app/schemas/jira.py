"""Pydantic schemas for Jira integration endpoints."""

from pydantic import BaseModel, Field


class JiraConnectRequest(BaseModel):
    """Initiate Jira OAuth connection."""

    code: str = Field(min_length=1, description="OAuth authorisation code")


class JiraConnectResponse(BaseModel):
    """Response after Jira OAuth connection."""

    connected: bool
    site_name: str = ""
    cloud_id: str = ""


class JiraStatusResponse(BaseModel):
    """Jira integration status."""

    connected: bool
    site_name: str = ""
    cloud_id: str = ""


class JiraCallbackRequest(BaseModel):
    """OAuth callback request."""

    code: str = Field(min_length=1)
    state: str = ""
