"""Tests for scan progress service (D20 #36)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services.scan_progress_service import SCAN_STAGES, publish_progress


@pytest.mark.asyncio
async def test_publish_sends_to_redis() -> None:
    """publish_progress publishes a JSON message to the correct Redis channel."""
    fake_redis = AsyncMock()

    with patch("app.services.scan_progress_service.get_redis", return_value=fake_redis):
        await publish_progress("scan-123", "cloning", 10, "Cloning repository")

    fake_redis.publish.assert_awaited_once()
    channel, payload = fake_redis.publish.call_args[0]
    assert channel == "scan:scan-123"

    data = json.loads(payload)
    assert data["scan_id"] == "scan-123"
    assert data["status"] == "cloning"
    assert data["progress_pct"] == 10
    assert data["detail"] == "Cloning repository"


@pytest.mark.asyncio
async def test_progress_includes_all_fields() -> None:
    """Published payload must contain scan_id, status, progress_pct, detail, timestamp."""
    fake_redis = AsyncMock()

    with patch("app.services.scan_progress_service.get_redis", return_value=fake_redis):
        await publish_progress("scan-456", "scanning_pass1", 30, "Tree-sitter pass")

    _, payload = fake_redis.publish.call_args[0]
    data = json.loads(payload)

    required_fields = {"scan_id", "status", "progress_pct", "detail", "timestamp"}
    assert required_fields.issubset(data.keys())
    assert data["timestamp"]  # non-empty ISO timestamp


@pytest.mark.asyncio
async def test_stages_have_correct_percentages() -> None:
    """All defined stages map to the expected progress percentages."""
    expected = {
        "queued": 0,
        "cloning": 10,
        "scanning_pass1": 30,
        "scanning_pass2": 60,
        "generating_cbom": 85,
        "completed": 100,
        "failed": -1,
    }
    assert SCAN_STAGES == expected


@pytest.mark.asyncio
async def test_publish_skips_when_redis_unavailable() -> None:
    """publish_progress does not raise when Redis is None."""
    with patch("app.services.scan_progress_service.get_redis", return_value=None):
        # Should not raise
        await publish_progress("scan-999", "queued", 0)


@pytest.mark.asyncio
async def test_publish_default_detail_empty() -> None:
    """When detail is omitted, it defaults to empty string."""
    fake_redis = AsyncMock()

    with patch("app.services.scan_progress_service.get_redis", return_value=fake_redis):
        await publish_progress("scan-789", "completed", 100)

    _, payload = fake_redis.publish.call_args[0]
    data = json.loads(payload)
    assert data["detail"] == ""
