"""Notification engine — dispatch, in-app, email, and Teams webhook delivery.

Handles routing notifications to the correct channels based on trigger type,
user preferences, and organisation configuration.
"""

import json
import logging
import uuid as _uuid
from datetime import UTC, datetime

from jinja2 import Environment, PackageLoader, select_autoescape

from app.config import settings
from app.models.notification import Notification, NotificationSeverity, NotificationTrigger

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Jinja2 email template environment
# ---------------------------------------------------------------------------

_jinja_env = Environment(
    loader=PackageLoader("app", "templates/email"),
    autoescape=select_autoescape(["html"]),
)

# ---------------------------------------------------------------------------
# Trigger → severity mapping (from docs/10-communications.md)
# ---------------------------------------------------------------------------

TRIGGER_SEVERITY: dict[str, str] = {
    NotificationTrigger.T01_SCAN_COMPLETED: NotificationSeverity.INFO,
    NotificationTrigger.T02_SCAN_VIOLATIONS: NotificationSeverity.HIGH,
    NotificationTrigger.T03_CRITICAL_FINDING: NotificationSeverity.CRITICAL,
    NotificationTrigger.T06_CERT_EXPIRY_30D: NotificationSeverity.HIGH,
    NotificationTrigger.T11_SUPPRESSION_SUBMITTED: NotificationSeverity.MEDIUM,
}

# Severity → Adaptive Card accent colour
SEVERITY_COLOUR: dict[str, str] = {
    NotificationSeverity.INFO: "good",
    NotificationSeverity.MEDIUM: "warning",
    NotificationSeverity.HIGH: "warning",
    NotificationSeverity.CRITICAL: "attention",
}


class NotificationService:
    """Central notification dispatch engine.

    Coordinates delivery across in-app (DB + WebSocket/Redis Pub/Sub),
    email (SMTP), and Microsoft Teams (Incoming Webhook) channels.
    """

    def __init__(self) -> None:
        # Pluggable DB persistence callbacks — set by the app layer or tests.
        self._create_notification = None  # async (Notification) -> Notification
        self._get_user_preferences = None  # async (user_id, trigger_type) -> dict | None
        self._redis_client = None  # redis.asyncio.Redis instance

    # -- Setter helpers for DI / testing ------------------------------------

    def set_create_notification(self, fn) -> None:  # noqa: ANN001
        """Register async callback to persist a notification record."""
        self._create_notification = fn

    def set_get_user_preferences(self, fn) -> None:  # noqa: ANN001
        """Register async callback to fetch user notification preferences."""
        self._get_user_preferences = fn

    def set_redis_client(self, client) -> None:  # noqa: ANN001
        """Set the Redis client for Pub/Sub delivery."""
        self._redis_client = client

    # -- Main dispatch ------------------------------------------------------

    async def dispatch(self, trigger: str, context: dict) -> None:
        """Route a notification trigger to the appropriate channels.

        Args:
            trigger: One of ``NotificationTrigger`` values.
            context: Event-specific data including ``user_ids``, ``org_id``,
                ``title``, ``message``, ``link``, and optional channel-specific
                fields like ``email_recipients``, ``teams_webhook_url``.
        """
        severity = TRIGGER_SEVERITY.get(trigger, NotificationSeverity.INFO)
        user_ids: list[str] = context.get("user_ids", [])
        org_id: str = context.get("org_id", "")
        title: str = context.get("title", "CipherRadar Notification")
        message: str = context.get("message", "")
        link: str | None = context.get("link")

        # 1. In-app notifications for each target user
        for uid in user_ids:
            prefs = await self._load_preferences(uid, trigger)

            if prefs.get("in_app", True):
                await self.send_in_app(
                    user_id=_uuid.UUID(uid),
                    org_id=_uuid.UUID(org_id) if org_id else _uuid.UUID(int=0),
                    trigger_type=trigger,
                    severity=severity,
                    title=title,
                    message=message,
                    link=link,
                )

        # 2. Email
        email_recipients: list[str] = context.get("email_recipients", [])
        if email_recipients:
            subject = f"[{severity.upper()}] {title}"
            body_html = self.render_email_template(trigger, context)
            for recipient in email_recipients:
                await self.send_email(recipient, subject, body_html)

        # 3. Teams webhook
        teams_webhook_url: str | None = context.get("teams_webhook_url")
        if teams_webhook_url:
            card = self.build_teams_card(trigger, severity, title, message, link, context)
            await self.send_teams_webhook(teams_webhook_url, card)

    # -- In-app notification ------------------------------------------------

    async def send_in_app(
        self,
        user_id: _uuid.UUID,
        org_id: _uuid.UUID,
        trigger_type: str,
        severity: str,
        title: str,
        message: str,
        link: str | None = None,
    ) -> Notification:
        """Create an in-app notification and publish to Redis for WebSocket delivery."""
        notification = Notification(
            user_id=user_id,
            org_id=org_id,
            trigger_type=trigger_type,
            severity=severity,
            title=title,
            message=message,
            link=link,
            read=False,
        )
        notification.id = _uuid.uuid4()
        notification.created_at = datetime.now(UTC)

        if self._create_notification is not None:
            notification = await self._create_notification(notification)

        # Publish to Redis Pub/Sub for WebSocket fan-out
        await self._publish_ws(user_id, notification)

        return notification

    async def _publish_ws(self, user_id: _uuid.UUID, notification: Notification) -> None:
        """Publish notification to Redis Pub/Sub channel for the user."""
        if self._redis_client is None:
            return

        try:
            channel = f"notifications:{user_id}"
            payload = json.dumps({
                "id": str(notification.id),
                "trigger_type": notification.trigger_type,
                "severity": notification.severity,
                "title": notification.title,
                "message": notification.message,
                "link": notification.link,
                "created_at": notification.created_at.isoformat() if notification.created_at else None,
            })
            await self._redis_client.publish(channel, payload)
        except Exception:
            logger.warning("Failed to publish notification to Redis for user %s", user_id, exc_info=True)

    # -- Email --------------------------------------------------------------

    async def send_email(self, recipient: str, subject: str, body_html: str) -> None:
        """Send an email via async SMTP.

        Configuration is read from ``settings.smtp_*`` fields.
        """
        try:
            import aiosmtplib

            await aiosmtplib.send(
                message=self._build_email_message(recipient, subject, body_html),
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_user or None,
                password=settings.smtp_password or None,
                start_tls=True,
            )
        except Exception:
            logger.warning("Failed to send email to %s: %s", recipient, subject, exc_info=True)

    @staticmethod
    def _build_email_message(recipient: str, subject: str, body_html: str) -> str:
        """Build a minimal RFC 2822 MIME message."""
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from_address
        msg["To"] = recipient
        # Plain-text fallback
        msg.attach(MIMEText(subject, "plain"))
        msg.attach(MIMEText(body_html, "html"))
        return msg.as_string()

    def render_email_template(self, trigger: str, context: dict) -> str:
        """Render the Jinja2 email template for a given trigger.

        Falls back to `notification_base.html` if a trigger-specific template
        does not exist.
        """
        template_name = f"{trigger}.html"
        try:
            template = _jinja_env.get_template(template_name)
        except Exception:
            template = _jinja_env.get_template("notification_base.html")
        return template.render(**context)

    # -- Teams webhook ------------------------------------------------------

    async def send_teams_webhook(self, webhook_url: str, card: dict) -> None:
        """Post an Adaptive Card to a Microsoft Teams Incoming Webhook."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(webhook_url, json=card)
                if response.status_code >= 400:
                    logger.warning(
                        "Teams webhook returned %s for %s",
                        response.status_code,
                        webhook_url,
                    )
        except Exception:
            logger.warning("Failed to send Teams webhook to %s", webhook_url, exc_info=True)

    @staticmethod
    def build_teams_card(
        trigger: str,
        severity: str,
        title: str,
        message: str,
        link: str | None,
        context: dict,
    ) -> dict:
        """Build a Microsoft Teams Adaptive Card payload."""
        colour = SEVERITY_COLOUR.get(severity, "default")
        actions = []
        if link:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View in CipherRadar",
                "url": link,
            })

        body_items = [
            {
                "type": "TextBlock",
                "size": "medium",
                "weight": "bolder",
                "text": f"{severity.upper()} — {title}",
                "color": colour,
            },
            {
                "type": "TextBlock",
                "text": message,
                "wrap": True,
            },
        ]

        # Add finding details if present
        project_name = context.get("project_name")
        if project_name:
            body_items.append({
                "type": "TextBlock",
                "text": f"**Project:** {project_name}",
                "wrap": True,
            })

        file_location = context.get("file_location")
        if file_location:
            body_items.append({
                "type": "TextBlock",
                "text": f"**File:** {file_location}",
                "wrap": True,
            })

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body_items,
                        "actions": actions,
                    },
                }
            ],
        }

    # -- Preferences --------------------------------------------------------

    async def _load_preferences(self, user_id: str, trigger: str) -> dict:
        """Load user preferences for a trigger, with defaults."""
        if self._get_user_preferences is not None:
            prefs = await self._get_user_preferences(user_id, trigger)
            if prefs is not None:
                return prefs
        return {"in_app": True, "email": True, "teams": False}


# Module-level singleton
notification_service = NotificationService()
