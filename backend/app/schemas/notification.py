"""Pydantic schemas for notification endpoints."""

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from pydantic import Field

from app.schemas.base import CamelCaseModel

# ---------------------------------------------------------------------------
# Notification responses
# ---------------------------------------------------------------------------


class NotificationResponse(CamelCaseModel):
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

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class NotificationListResponse(CamelCaseModel):
    """Paginated list of notifications."""

    items: list[NotificationResponse]
    total: int
    page: int
    per_page: int


class MarkReadResponse(CamelCaseModel):
    """Response after marking notification(s) as read."""

    success: bool = True


# ---------------------------------------------------------------------------
# Notification preferences
# ---------------------------------------------------------------------------


class NotificationPreferenceItem(CamelCaseModel):
    """Preference for a single trigger type."""

    trigger_type: str
    in_app: bool = True
    email: bool = True
    teams: bool = False


class NotificationPreferencesResponse(CamelCaseModel):
    """Full set of user notification preferences."""

    preferences: list[NotificationPreferenceItem]


class NotificationPreferencesUpdate(CamelCaseModel):
    """Update request for notification preferences."""

    preferences: list[NotificationPreferenceItem] = Field(min_length=1)


# ---------------------------------------------------------------------------
# WebSocket message
# ---------------------------------------------------------------------------


class WSNotificationMessage(CamelCaseModel):
    """Notification payload pushed over WebSocket / Redis Pub/Sub."""

    id: uuid.UUID
    trigger_type: str
    severity: str
    title: str
    message: str
    link: str | None = None
    created_at: datetime
