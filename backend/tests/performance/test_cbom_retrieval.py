"""Performance tests for CBOM retrieval with caching.

These are mock-based tests that verify caching logic works correctly,
not actual HTTP load tests.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services.cache_service import (
    CBOM_CACHE_TTL,
    get_cached_cbom,
    set_cached_cbom,
)


@pytest.mark.asyncio
async def test_cache_miss_returns_none() -> None:
    """When Redis has no cached CBOM, get_cached_cbom should return None."""
    # With no Redis client initialised, should return None
    result = await get_cached_cbom("nonexistent-scan-id")
    assert result is None


@pytest.mark.asyncio
async def test_cache_set_and_get_roundtrip() -> None:
    """Verify that set_cached_cbom stores data and get_cached_cbom retrieves it."""
    mock_redis = AsyncMock()
    sample_cbom = {"specVersion": "1.7", "components": [{"name": "AES-256"}]}

    # Mock the get to return what was set
    mock_redis.get = AsyncMock(return_value=json.dumps(sample_cbom))
    mock_redis.set = AsyncMock()

    with patch("app.services.cache_service._redis_client", mock_redis):
        await set_cached_cbom("scan-123", sample_cbom)
        mock_redis.set.assert_called_once_with(
            "cbom:scan-123",
            json.dumps(sample_cbom),
            ex=CBOM_CACHE_TTL,
        )

        result = await get_cached_cbom("scan-123")
        mock_redis.get.assert_called_once_with("cbom:scan-123")
        assert result == sample_cbom


@pytest.mark.asyncio
async def test_cache_ttl_is_one_hour() -> None:
    """Cache TTL should be 3600 seconds (1 hour)."""
    assert CBOM_CACHE_TTL == 3600


@pytest.mark.asyncio
async def test_cache_key_format() -> None:
    """Cache key should be 'cbom:{scan_id}'."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("app.services.cache_service._redis_client", mock_redis):
        await get_cached_cbom("abc-def-123")
        mock_redis.get.assert_called_once_with("cbom:abc-def-123")


@pytest.mark.asyncio
async def test_cache_graceful_on_redis_failure() -> None:
    """Cache operations should not raise even if Redis fails."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
    mock_redis.set = AsyncMock(side_effect=ConnectionError("Redis down"))

    with patch("app.services.cache_service._redis_client", mock_redis):
        # Should not raise, should return None
        result = await get_cached_cbom("scan-123")
        assert result is None

        # Should not raise
        await set_cached_cbom("scan-123", {"components": []})


@pytest.mark.asyncio
async def test_cached_response_matches_original() -> None:
    """Cached CBOM data should be identical to original after roundtrip."""
    original = {
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:test",
        "components": [
            {"name": "RSA-2048", "type": "crypto-asset"},
            {"name": "AES-256-GCM", "type": "crypto-asset"},
        ],
    }

    stored_json = json.dumps(original)
    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock()
    mock_redis.get = AsyncMock(return_value=stored_json)

    with patch("app.services.cache_service._redis_client", mock_redis):
        await set_cached_cbom("scan-456", original)
        result = await get_cached_cbom("scan-456")
        assert result == original
