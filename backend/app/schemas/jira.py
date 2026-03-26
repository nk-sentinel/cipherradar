"""Pydantic schemas for Jira integration endpoints."""

from __future__ import annotations

import uuid  # noqa: TCH003 — required at runtime for Pydantic

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


# ---------------------------------------------------------------------------
# D18 — Jira config & issue creation schemas
# ---------------------------------------------------------------------------


class JiraConfigResponse(CamelCaseModel):
    """Jira configuration for a group or project scope."""

    id: uuid.UUID
    jira_project_key: str
    default_issue_type: str
    priority_mapping: dict
    custom_fields: dict
    default_assignee: str | None
    labels: list[str]
    scope: str  # "group" or "project"

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class JiraConfigUpdate(CamelCaseModel):
    """Payload for creating/updating Jira config at group or project level."""

    jira_project_key: str
    default_issue_type: str = "Bug"
    priority_mapping: dict = {}
    custom_fields: dict = {}
    default_assignee: str | None = None
    labels: list[str] = []


class JiraIssueResponse(CamelCaseModel):
    """Response after creating a Jira issue for a finding."""

    issue_key: str
    issue_url: str
    summary: str
