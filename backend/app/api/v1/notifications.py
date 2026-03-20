"""Notification API endpoints — list, mark read, and manage preferences."""

import logging
import uuid

from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.notification import (
    MarkReadResponse,
    NotificationListResponse,
    NotificationPreferencesResponse,
    NotificationPreferencesUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])

# ---------------------------------------------------------------------------
# Pluggable callbacks — tests and the app layer can monkeypatch these.
# ---------------------------------------------------------------------------
_list_notifications = None  # async (user_id, page, per_page) -> NotificationListResponse
_mark_read = None  # async (notification_id, user_id) -> bool
_mark_all_read = None  # async (user_id) -> int
_get_preferences = None  # async (user_id) -> NotificationPreferencesResponse
_update_preferences = None  # async (user_id, prefs) -> NotificationPreferencesResponse


def set_list_notifications(fn) -> None:  # noqa: ANN001
    global _list_notifications  # noqa: PLW0603
    _list_notifications = fn


def set_mark_read(fn) -> None:  # noqa: ANN001
    global _mark_read  # noqa: PLW0603
    _mark_read = fn


def set_mark_all_read(fn) -> None:  # noqa: ANN001
    global _mark_all_read  # noqa: PLW0603
    _mark_all_read = fn


def set_get_preferences(fn) -> None:  # noqa: ANN001
    global _get_preferences  # noqa: PLW0603
    _get_preferences = fn


def set_update_preferences(fn) -> None:  # noqa: ANN001
    global _update_preferences  # noqa: PLW0603
    _update_preferences = fn


# ---------------------------------------------------------------------------
# GET /api/v1/notifications
# ---------------------------------------------------------------------------


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    user_id: uuid.UUID = Query(description="User ID to filter notifications"),
) -> NotificationListResponse:
    """List notifications for a user (paginated)."""
    if _list_notifications is not None:
        return await _list_notifications(str(user_id), page, per_page)

    return NotificationListResponse(items=[], total=0, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# PATCH /api/v1/notifications/{id}/read
# ---------------------------------------------------------------------------


@router.patch("/{notification_id}/read", response_model=MarkReadResponse)
async def mark_notification_read(
    notification_id: uuid.UUID,
) -> MarkReadResponse:
    """Mark a single notification as read."""
    if _mark_read is not None:
        success = await _mark_read(str(notification_id), "")
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found",
            )
        return MarkReadResponse(success=True)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Notification backend not configured",
    )


# ---------------------------------------------------------------------------
# POST /api/v1/notifications/read-all
# ---------------------------------------------------------------------------


@router.post("/read-all", response_model=MarkReadResponse)
async def mark_all_read(
    user_id: uuid.UUID = Query(description="User ID"),
) -> MarkReadResponse:
    """Mark all notifications for a user as read."""
    if _mark_all_read is not None:
        await _mark_all_read(str(user_id))
        return MarkReadResponse(success=True)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Notification backend not configured",
    )


# ---------------------------------------------------------------------------
# GET /api/v1/notifications/preferences
# ---------------------------------------------------------------------------


@router.get("/preferences", response_model=NotificationPreferencesResponse)
async def get_preferences(
    user_id: uuid.UUID = Query(description="User ID"),
) -> NotificationPreferencesResponse:
    """Get notification preferences for a user."""
    if _get_preferences is not None:
        return await _get_preferences(str(user_id))

    return NotificationPreferencesResponse(preferences=[])


# ---------------------------------------------------------------------------
# PUT /api/v1/notifications/preferences
# ---------------------------------------------------------------------------


@router.put("/preferences", response_model=NotificationPreferencesResponse)
async def update_preferences(
    body: NotificationPreferencesUpdate,
    user_id: uuid.UUID = Query(description="User ID"),
) -> NotificationPreferencesResponse:
    """Update notification preferences for a user."""
    if _update_preferences is not None:
        return await _update_preferences(str(user_id), body)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Notification backend not configured",
    )
