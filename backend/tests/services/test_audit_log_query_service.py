"""Tests for enhanced audit log query service (D28)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.audit_log import AuditLog
from app.schemas.pagination import PaginatedResponse
from app.services.audit_log_query_service import AuditLogQueryService


_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()


def _make_audit_entry(
    action_type: str = "user.login",
    resource_type: str = "user",
) -> MagicMock:
    entry = MagicMock(spec=AuditLog)
    entry.id = uuid.uuid4()
    entry.org_id = _ORG_ID
    entry.user_id = _USER_ID
    entry.action_type = action_type
    entry.resource_type = resource_type
    entry.resource_id = uuid.uuid4()
    entry.details = {"key": "value"}
    entry.ip_address = "192.168.1.1"
    entry.user_agent = "TestAgent"
    entry.created_at = datetime.now(UTC)
    return entry


class TestQuery:
    """Test filtered paginated query."""

    @pytest.mark.asyncio
    async def test_query_returns_paginated_results(self) -> None:
        svc = AuditLogQueryService()
        entry = _make_audit_entry()

        mock_page = PaginatedResponse(
            items=[entry],
            total=1,
            page=1,
            per_page=25,
        )

        with patch("app.services.audit_log_query_service.paginate", new_callable=AsyncMock, return_value=mock_page):
            session = AsyncMock()
            result = await svc.query(str(_ORG_ID), session)

        assert result["total"] == 1
        assert result["page"] == 1
        assert len(result["items"]) == 1

    @pytest.mark.asyncio
    async def test_query_with_date_filters(self) -> None:
        svc = AuditLogQueryService()
        mock_page = PaginatedResponse(items=[], total=0, page=1, per_page=25)

        with patch("app.services.audit_log_query_service.paginate", new_callable=AsyncMock, return_value=mock_page):
            session = AsyncMock()
            result = await svc.query(
                str(_ORG_ID),
                session,
                date_from=datetime(2024, 1, 1, tzinfo=UTC),
                date_to=datetime(2024, 12, 31, tzinfo=UTC),
            )

        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_query_with_action_type_filter(self) -> None:
        svc = AuditLogQueryService()
        entry = _make_audit_entry(action_type="policy.updated")
        mock_page = PaginatedResponse(items=[entry], total=1, page=1, per_page=25)

        with patch("app.services.audit_log_query_service.paginate", new_callable=AsyncMock, return_value=mock_page):
            session = AsyncMock()
            result = await svc.query(
                str(_ORG_ID),
                session,
                action_type="policy.updated",
            )

        assert len(result["items"]) == 1

    @pytest.mark.asyncio
    async def test_query_with_user_id_filter(self) -> None:
        svc = AuditLogQueryService()
        mock_page = PaginatedResponse(items=[], total=0, page=1, per_page=25)

        with patch("app.services.audit_log_query_service.paginate", new_callable=AsyncMock, return_value=mock_page):
            session = AsyncMock()
            result = await svc.query(
                str(_ORG_ID),
                session,
                user_id=str(_USER_ID),
            )

        assert result["total"] == 0


class TestExportCSV:
    """Test CSV export."""

    @pytest.mark.asyncio
    async def test_export_csv_format(self) -> None:
        svc = AuditLogQueryService()
        entry = _make_audit_entry()

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [entry]
        mock_result.scalars.return_value = mock_scalars
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        csv_content = await svc.export_csv(str(_ORG_ID), session)

        assert "id" in csv_content
        assert "timestamp" in csv_content
        assert "action_type" in csv_content
        lines = csv_content.strip().split("\n")
        assert len(lines) == 2  # header + 1 entry


class TestWebhookForwarding:
    """Test webhook forwarding."""

    @pytest.mark.asyncio
    async def test_webhook_success(self) -> None:
        svc = AuditLogQueryService()

        with patch("app.services.audit_log_query_service.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await svc.forward_to_webhook(
                "https://example.com/webhook",
                {"action_type": "test"},
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_webhook_empty_url_returns_false(self) -> None:
        svc = AuditLogQueryService()
        result = await svc.forward_to_webhook("", {"action_type": "test"})
        assert result is False

    @pytest.mark.asyncio
    async def test_webhook_failure(self) -> None:
        svc = AuditLogQueryService()

        with patch("app.services.audit_log_query_service.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await svc.forward_to_webhook(
                "https://example.com/webhook",
                {"action_type": "test"},
            )

        assert result is False
