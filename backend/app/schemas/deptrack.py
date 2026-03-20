"""Pydantic schemas for Dependency-Track integration endpoints."""

from pydantic import BaseModel, Field


class DepTrackConnectRequest(BaseModel):
    """Save Dependency-Track connection details."""

    base_url: str = Field(min_length=1, description="Dependency-Track base URL (e.g. https://dt.example.com)")
    api_key: str = Field(min_length=1, description="Dependency-Track API key")


class DepTrackConnectResponse(BaseModel):
    """Response after saving Dependency-Track connection."""

    connected: bool
    base_url: str = ""
    message: str = ""


class DepTrackStatusResponse(BaseModel):
    """Dependency-Track integration connection status."""

    connected: bool
    base_url: str = ""
    server_version: str = ""
    message: str = ""


class DepTrackSyncResponse(BaseModel):
    """Response after syncing a scan to Dependency-Track."""

    synced: bool
    project_uuid: str = ""
    token: str = ""
    message: str = ""
