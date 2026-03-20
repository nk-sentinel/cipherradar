"""Performance tests for portfolio endpoints — cached vs uncached (mock Redis)."""

import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.portfolio import (
    MigrationPriorityItem,
    PortfolioQuantum,
    PortfolioSummary,
    QuantumCategory,
)
from app.services.portfolio_service import (
    PORTFOLIO_CACHE_TTL,
    _cache_key,
    invalidate_portfolio_cache,
)

FAKE_USER_ID = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Cache key format
# ---------------------------------------------------------------------------


def test_cache_key_format() -> None:
    """Cache keys should be 'portfolio:{endpoint}:{user_id}'."""
    key = _cache_key("user-123", "summary")
    assert key == "portfolio:summary:user-123"

    key = _cache_key("user-456", "compliance")
    assert key == "portfolio:compliance:user-456"

    key = _cache_key("user-789", "quantum")
    assert key == "portfolio:quantum:user-789"


# ---------------------------------------------------------------------------
# Cache TTL
# ---------------------------------------------------------------------------


def test_cache_ttl_is_five_minutes() -> None:
    """Portfolio cache TTL should be 300 seconds (5 minutes)."""
    assert PORTFOLIO_CACHE_TTL == 300


# ---------------------------------------------------------------------------
# Cached vs uncached — summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cached_summary_returns_without_db_query() -> None:
    """When cache has data, get_portfolio_summary should return without querying DB."""
    cached_data = PortfolioSummary(
        total_repos=3,
        total_findings=20,
        quantum_readiness_pct=75.0,
        heat_map=[],
        top_riskiest_repos=[],
    ).model_dump()

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(cached_data))

    mock_session = AsyncMock()

    with patch("app.services.portfolio_service.get_redis", return_value=mock_redis):
        from app.services.portfolio_service import get_portfolio_summary

        result = await get_portfolio_summary(
            mock_session,
            [uuid.uuid4()],
            FAKE_USER_ID,
        )

    assert result.total_repos == 3
    assert result.total_findings == 20
    assert result.quantum_readiness_pct == 75.0

    # DB session should NOT have been used for execute
    mock_session.execute.assert_not_called()

    # Redis get should have been called
    mock_redis.get.assert_called_once()


# ---------------------------------------------------------------------------
# Cache miss triggers DB query
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_miss_triggers_computation() -> None:
    """When cache misses, get_portfolio_summary should query the DB and cache result."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()

    # No project_ids -> empty result, but should still cache
    mock_session = AsyncMock()

    with patch("app.services.portfolio_service.get_redis", return_value=mock_redis):
        from app.services.portfolio_service import get_portfolio_summary

        result = await get_portfolio_summary(mock_session, [], FAKE_USER_ID)

    assert result.total_repos == 0
    assert result.total_findings == 0

    # Should have written to cache
    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    assert call_args[1]["ex"] == PORTFOLIO_CACHE_TTL


# ---------------------------------------------------------------------------
# Cache invalidation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalidate_portfolio_cache() -> None:
    """invalidate_portfolio_cache should delete all 3 endpoint keys for the user."""
    mock_redis = AsyncMock()
    mock_redis.delete = AsyncMock()

    with patch("app.services.portfolio_service.get_redis", return_value=mock_redis):
        await invalidate_portfolio_cache(FAKE_USER_ID)

    # Should delete 3 keys: summary, compliance, quantum
    assert mock_redis.delete.call_count == 3
    deleted_keys = {call.args[0] for call in mock_redis.delete.call_args_list}
    assert f"portfolio:summary:{FAKE_USER_ID}" in deleted_keys
    assert f"portfolio:compliance:{FAKE_USER_ID}" in deleted_keys
    assert f"portfolio:quantum:{FAKE_USER_ID}" in deleted_keys


# ---------------------------------------------------------------------------
# Cache graceful on Redis failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_graceful_on_redis_failure() -> None:
    """Portfolio cache operations should not raise even if Redis fails."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
    mock_redis.set = AsyncMock(side_effect=ConnectionError("Redis down"))

    mock_session = AsyncMock()

    with patch("app.services.portfolio_service.get_redis", return_value=mock_redis):
        from app.services.portfolio_service import get_portfolio_summary

        # Should not raise — falls through to computation with empty project list
        result = await get_portfolio_summary(mock_session, [], FAKE_USER_ID)

    assert result.total_repos == 0


# ---------------------------------------------------------------------------
# Cached quantum data matches original
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cached_quantum_matches_original() -> None:
    """Cached PortfolioQuantum should be identical after JSON roundtrip."""
    original = PortfolioQuantum(
        counts=QuantumCategory(vulnerable=5, safe=10, broken=2, unknown=1),
        migration_priority=[
            MigrationPriorityItem(
                algorithm="rsa",
                total_count=3,
                affected_repos=2,
                migrate_to="ml-dsa",
                priority=1,
            ),
        ],
    )

    serialized = json.dumps(original.model_dump())
    deserialized = PortfolioQuantum(**json.loads(serialized))

    assert deserialized.counts.vulnerable == original.counts.vulnerable
    assert deserialized.counts.safe == original.counts.safe
    assert deserialized.counts.broken == original.counts.broken
    assert deserialized.counts.unknown == original.counts.unknown
    assert len(deserialized.migration_priority) == 1
    assert deserialized.migration_priority[0].algorithm == "rsa"


# ---------------------------------------------------------------------------
# Redis unavailable — still works
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_redis_still_works() -> None:
    """When Redis is None, portfolio operations should still work (no caching)."""
    with patch("app.services.portfolio_service.get_redis", return_value=None):
        from app.services.portfolio_service import get_portfolio_summary

        mock_session = AsyncMock()
        result = await get_portfolio_summary(mock_session, [], "user-no-redis")

    assert result.total_repos == 0
    assert result.quantum_readiness_pct == 100.0
