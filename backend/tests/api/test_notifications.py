"""Tests for notification API endpoints — list, mark read, preferences."""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1 import notifications as notifications_mod
from app.main import create_app
from app.schemas.notification import (
    NotificationListResponse,
    NotificationPreferenceItem,
    NotificationPreferencesResponse,
    NotificationResponse,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_USER_ID = uuid.uuid4()
FAKE_ORG_ID = uuid.uuid4()
FAKE_NOTIF_ID = uuid.uuid4()
NOW = datetime.now(UTC)


@pytest.fixture
def app():
    """Create a test app without lifespan."""
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    """Async HTTP client wired to the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


def _make_notification_response() -> NotificationResponse:
    return NotificationResponse(
        id=FAKE_NOTIF_ID,
        user_id=FAKE_USER_ID,
        org_id=FAKE_ORG_ID,
        trigger_type="scan_completed",
        severity="info",
        title="Scan completed",
        message="No violations found",
        link="/scans/123",
        read=False,
        created_at=NOW,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/notifications
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_notifications_returns_paginated(client: AsyncClient) -> None:
    """GET /api/v1/notifications should return paginated results."""
    mock_list = AsyncMock(
        return_value=NotificationListResponse(
            items=[_make_notification_response()],
            total=1,
            page=1,
            per_page=20,
        )
    )
    original = notifications_mod._list_notifications
    notifications_mod._list_notifications = mock_list

    try:
        response = await client.get(f"/api/v1/notifications?user_id={FAKE_USER_ID}&page=1&per_page=20")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["page"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["trigger_type"] == "scan_completed"
    finally:
        notifications_mod._list_notifications = original


@pytest.mark.asyncio
async def test_list_notifications_empty_without_backend(client: AsyncClient) -> None:
    """GET /api/v1/notifications should return empty list when no backend is configured."""
    original = notifications_mod._list_notifications
    notifications_mod._list_notifications = None

    try:
        response = await client.get(f"/api/v1/notifications?user_id={FAKE_USER_ID}")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 0
        assert body["items"] == []
    finally:
        notifications_mod._list_notifications = original


# ---------------------------------------------------------------------------
# PATCH /api/v1/notifications/{id}/read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_read_returns_success(client: AsyncClient) -> None:
    """PATCH /api/v1/notifications/{id}/read should mark a notification as read."""
    mock_mark = AsyncMock(return_value=True)
    original = notifications_mod._mark_read
    notifications_mod._mark_read = mock_mark

    try:
        response = await client.patch(f"/api/v1/notifications/{FAKE_NOTIF_ID}/read")
        assert response.status_code == 200
        assert response.json()["success"] is True
    finally:
        notifications_mod._mark_read = original


@pytest.mark.asyncio
async def test_mark_read_returns_404_when_not_found(client: AsyncClient) -> None:
    """PATCH /api/v1/notifications/{id}/read should return 404 for missing notification."""
    mock_mark = AsyncMock(return_value=False)
    original = notifications_mod._mark_read
    notifications_mod._mark_read = mock_mark

    try:
        response = await client.patch(f"/api/v1/notifications/{uuid.uuid4()}/read")
        assert response.status_code == 404
    finally:
        notifications_mod._mark_read = original


# ---------------------------------------------------------------------------
# POST /api/v1/notifications/read-all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_all_read_returns_success(client: AsyncClient) -> None:
    """POST /api/v1/notifications/read-all should mark all as read."""
    mock_mark_all = AsyncMock(return_value=5)
    original = notifications_mod._mark_all_read
    notifications_mod._mark_all_read = mock_mark_all

    try:
        response = await client.post(f"/api/v1/notifications/read-all?user_id={FAKE_USER_ID}")
        assert response.status_code == 200
        assert response.json()["success"] is True
    finally:
        notifications_mod._mark_all_read = original


# ---------------------------------------------------------------------------
# GET /api/v1/notifications/preferences
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_preferences_returns_prefs(client: AsyncClient) -> None:
    """GET /api/v1/notifications/preferences should return user preferences."""
    mock_get = AsyncMock(
        return_value=NotificationPreferencesResponse(
            preferences=[
                NotificationPreferenceItem(trigger_type="scan_completed", in_app=True, email=True, teams=False),
            ]
        )
    )
    original = notifications_mod._get_preferences
    notifications_mod._get_preferences = mock_get

    try:
        response = await client.get(f"/api/v1/notifications/preferences?user_id={FAKE_USER_ID}")
        assert response.status_code == 200
        body = response.json()
        assert len(body["preferences"]) == 1
        assert body["preferences"][0]["trigger_type"] == "scan_completed"
    finally:
        notifications_mod._get_preferences = original


# ---------------------------------------------------------------------------
# PUT /api/v1/notifications/preferences
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_preferences_returns_updated(client: AsyncClient) -> None:
    """PUT /api/v1/notifications/preferences should update and return preferences."""
    mock_update = AsyncMock(
        return_value=NotificationPreferencesResponse(
            preferences=[
                NotificationPreferenceItem(trigger_type="scan_completed", in_app=True, email=False, teams=True),
            ]
        )
    )
    original = notifications_mod._update_preferences
    notifications_mod._update_preferences = mock_update

    try:
        response = await client.put(
            f"/api/v1/notifications/preferences?user_id={FAKE_USER_ID}",
            json={
                "preferences": [
                    {"trigger_type": "scan_completed", "in_app": True, "email": False, "teams": True},
                ]
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["preferences"][0]["email"] is False
        assert body["preferences"][0]["teams"] is True
    finally:
        notifications_mod._update_preferences = original
