"""Pydantic schemas for Dependency-Track integration endpoints."""

from pydantic import Field

from app.schemas.base import CamelCaseModel


class DepTrackConnectRequest(CamelCaseModel):
    """Save Dependency-Track connection details."""

    base_url: str = Field(min_length=1, description="Dependency-Track base URL (e.g. https://dt.example.com)")
    api_key: str = Field(min_length=1, description="Dependency-Track API key")


class DepTrackConnectResponse(CamelCaseModel):
    """Response after saving Dependency-Track connection."""

    connected: bool
    base_url: str = ""
    message: str = ""


class DepTrackStatusResponse(CamelCaseModel):
    """Dependency-Track integration connection status."""

    connected: bool
    base_url: str = ""
    server_version: str = ""
    message: str = ""


class DepTrackSyncResponse(CamelCaseModel):
    """Response after syncing a scan to Dependency-Track."""

    synced: bool
    project_uuid: str = ""
    token: str = ""
    message: str = ""
