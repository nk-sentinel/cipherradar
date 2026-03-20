"""Pydantic schemas for notification endpoints."""

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Notification responses
# ---------------------------------------------------------------------------


class NotificationResponse(BaseModel):
    """Single notification."""

    id: uuid.UUID
    user_id: uuid.UUID
    org_id: uuid.UUID
    trigger_type: str
    severity: str
    title: str
    message: str
    link: str | None
    read: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class NotificationListResponse(BaseModel):
    """Paginated list of notifications."""

    items: list[NotificationResponse]
    total: int
    page: int
    per_page: int


class MarkReadResponse(BaseModel):
    """Response after marking notification(s) as read."""

    success: bool = True


# ---------------------------------------------------------------------------
# Notification preferences
# ---------------------------------------------------------------------------


class NotificationPreferenceItem(BaseModel):
    """Preference for a single trigger type."""

    trigger_type: str
    in_app: bool = True
    email: bool = True
    teams: bool = False


class NotificationPreferencesResponse(BaseModel):
    """Full set of user notification preferences."""

    preferences: list[NotificationPreferenceItem]


class NotificationPreferencesUpdate(BaseModel):
    """Update request for notification preferences."""

    preferences: list[NotificationPreferenceItem] = Field(min_length=1)


# ---------------------------------------------------------------------------
# WebSocket message
# ---------------------------------------------------------------------------


class WSNotificationMessage(BaseModel):
    """Notification payload pushed over WebSocket / Redis Pub/Sub."""

    id: uuid.UUID
    trigger_type: str
    severity: str
    title: str
    message: str
    link: str | None = None
    created_at: datetime
