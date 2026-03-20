"""Tests for the notification service — dispatch routing, email template rendering, in-app creation."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.models.notification import NotificationSeverity, NotificationTrigger
from app.services.notification_service import TRIGGER_SEVERITY, NotificationService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def notification_svc() -> NotificationService:
    """Fresh NotificationService with mocked persistence."""
    svc = NotificationService()
    svc.set_create_notification(AsyncMock(side_effect=lambda n: n))
    svc.set_get_user_preferences(AsyncMock(return_value=None))
    return svc


FAKE_USER_ID = str(uuid.uuid4())
FAKE_ORG_ID = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Dispatch routing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_creates_in_app_notifications(notification_svc: NotificationService) -> None:
    """dispatch() should create in-app notifications for all target users."""
    user_ids = [str(uuid.uuid4()), str(uuid.uuid4())]

    await notification_svc.dispatch(
        trigger=NotificationTrigger.T01_SCAN_COMPLETED,
        context={
            "user_ids": user_ids,
            "org_id": FAKE_ORG_ID,
            "title": "Scan completed",
            "message": "No violations found",
        },
    )

    assert notification_svc._create_notification.call_count == 2


@pytest.mark.asyncio
async def test_dispatch_respects_trigger_severity(notification_svc: NotificationService) -> None:
    """dispatch() should assign correct severity based on trigger type."""
    user_ids = [FAKE_USER_ID]

    await notification_svc.dispatch(
        trigger=NotificationTrigger.T03_CRITICAL_FINDING,
        context={
            "user_ids": user_ids,
            "org_id": FAKE_ORG_ID,
            "title": "Critical finding",
            "message": "RSA-1024 detected",
        },
    )

    call_args = notification_svc._create_notification.call_args[0][0]
    assert call_args.severity == NotificationSeverity.CRITICAL


@pytest.mark.asyncio
async def test_dispatch_sends_email_when_recipients_present(notification_svc: NotificationService) -> None:
    """dispatch() should call send_email for each email recipient."""
    with patch.object(notification_svc, "send_email", new_callable=AsyncMock) as mock_email:
        await notification_svc.dispatch(
            trigger=NotificationTrigger.T02_SCAN_VIOLATIONS,
            context={
                "user_ids": [],
                "org_id": FAKE_ORG_ID,
                "title": "Policy violations",
                "message": "3 violations found",
                "email_recipients": ["alice@example.com", "bob@example.com"],
            },
        )

        assert mock_email.call_count == 2


@pytest.mark.asyncio
async def test_dispatch_sends_teams_webhook_when_url_present(notification_svc: NotificationService) -> None:
    """dispatch() should call send_teams_webhook when teams_webhook_url is provided."""
    with patch.object(notification_svc, "send_teams_webhook", new_callable=AsyncMock) as mock_teams:
        await notification_svc.dispatch(
            trigger=NotificationTrigger.T03_CRITICAL_FINDING,
            context={
                "user_ids": [],
                "org_id": FAKE_ORG_ID,
                "title": "Critical finding",
                "message": "RSA-1024",
                "teams_webhook_url": "https://teams.example.com/webhook",
            },
        )

        mock_teams.assert_called_once()


@pytest.mark.asyncio
async def test_dispatch_skips_email_when_no_recipients(notification_svc: NotificationService) -> None:
    """dispatch() should not call send_email when no email_recipients are set."""
    with patch.object(notification_svc, "send_email", new_callable=AsyncMock) as mock_email:
        await notification_svc.dispatch(
            trigger=NotificationTrigger.T01_SCAN_COMPLETED,
            context={
                "user_ids": [FAKE_USER_ID],
                "org_id": FAKE_ORG_ID,
                "title": "Scan done",
                "message": "Done",
            },
        )

        mock_email.assert_not_called()


# ---------------------------------------------------------------------------
# In-app creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_in_app_creates_notification(notification_svc: NotificationService) -> None:
    """send_in_app() should persist a notification via the callback."""
    notif = await notification_svc.send_in_app(
        user_id=uuid.UUID(FAKE_USER_ID),
        org_id=uuid.UUID(FAKE_ORG_ID),
        trigger_type=NotificationTrigger.T06_CERT_EXPIRY_30D,
        severity=NotificationSeverity.HIGH,
        title="Certificate expiring",
        message="cert.pem expires in 15 days",
        link="/projects/abc/cert/xyz",
    )

    notification_svc._create_notification.assert_called_once()
    assert notif.title == "Certificate expiring"
    assert notif.severity == NotificationSeverity.HIGH
    assert notif.read is False


@pytest.mark.asyncio
async def test_send_in_app_publishes_to_redis(notification_svc: NotificationService) -> None:
    """send_in_app() should publish to Redis Pub/Sub when client is set."""
    mock_redis = AsyncMock()
    notification_svc.set_redis_client(mock_redis)

    await notification_svc.send_in_app(
        user_id=uuid.UUID(FAKE_USER_ID),
        org_id=uuid.UUID(FAKE_ORG_ID),
        trigger_type=NotificationTrigger.T01_SCAN_COMPLETED,
        severity=NotificationSeverity.INFO,
        title="Scan done",
        message="No issues",
    )

    mock_redis.publish.assert_called_once()
    channel = mock_redis.publish.call_args[0][0]
    assert channel == f"notifications:{FAKE_USER_ID}"


# ---------------------------------------------------------------------------
# Email template rendering
# ---------------------------------------------------------------------------


def test_render_email_template_returns_html(notification_svc: NotificationService) -> None:
    """render_email_template() should return a non-empty HTML string."""
    html = notification_svc.render_email_template(
        NotificationTrigger.T01_SCAN_COMPLETED,
        {
            "title": "Scan completed",
            "message": "No violations",
            "project_name": "auth-service",
            "severity": "info",
        },
    )
    assert "<html" in html
    assert "auth-service" in html


def test_render_email_template_fallback_to_base(notification_svc: NotificationService) -> None:
    """render_email_template() should use notification_base.html for unknown triggers."""
    html = notification_svc.render_email_template(
        "unknown_trigger",
        {"title": "Test", "message": "Test message", "severity": "info"},
    )
    assert "<html" in html
    assert "Test message" in html


# ---------------------------------------------------------------------------
# Teams card building
# ---------------------------------------------------------------------------


def test_build_teams_card_structure() -> None:
    """build_teams_card() should return a valid Adaptive Card payload."""
    card = NotificationService.build_teams_card(
        trigger=NotificationTrigger.T03_CRITICAL_FINDING,
        severity=NotificationSeverity.CRITICAL,
        title="RSA-1024 detected",
        message="quantum-vulnerable algorithm found",
        link="https://cipherradar.io/findings/123",
        context={"project_name": "auth-service", "file_location": "src/crypto.java:42"},
    )

    assert card["type"] == "message"
    assert len(card["attachments"]) == 1
    content = card["attachments"][0]["content"]
    assert content["type"] == "AdaptiveCard"
    assert len(content["actions"]) == 1
    assert content["actions"][0]["url"] == "https://cipherradar.io/findings/123"


# ---------------------------------------------------------------------------
# Trigger severity mapping
# ---------------------------------------------------------------------------


def test_trigger_severity_mapping() -> None:
    """All 5 core triggers should have severity mappings."""
    assert TRIGGER_SEVERITY[NotificationTrigger.T01_SCAN_COMPLETED] == NotificationSeverity.INFO
    assert TRIGGER_SEVERITY[NotificationTrigger.T02_SCAN_VIOLATIONS] == NotificationSeverity.HIGH
    assert TRIGGER_SEVERITY[NotificationTrigger.T03_CRITICAL_FINDING] == NotificationSeverity.CRITICAL
    assert TRIGGER_SEVERITY[NotificationTrigger.T06_CERT_EXPIRY_30D] == NotificationSeverity.HIGH
    assert TRIGGER_SEVERITY[NotificationTrigger.T11_SUPPRESSION_SUBMITTED] == NotificationSeverity.MEDIUM
