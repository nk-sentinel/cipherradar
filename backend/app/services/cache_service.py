"""Redis caching service for CBOM retrieval and other cacheable data."""

import json
import logging

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)

# Default TTL: 1 hour (scans are immutable once completed)
CBOM_CACHE_TTL = 3600

_redis_client: redis.Redis | None = None


async def init_redis() -> None:
    """Initialize the Redis connection pool. Called during app startup."""
    global _redis_client  # noqa: PLW0603
    _redis_client = redis.from_url(settings.redis_url, decode_responses=True)


async def close_redis() -> None:
    """Close the Redis connection. Called during app shutdown."""
    global _redis_client  # noqa: PLW0603
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


def get_redis() -> redis.Redis | None:
    """Return the current Redis client (may be None if not initialised)."""
    return _redis_client


async def get_cached_cbom(scan_id: str) -> dict | None:
    """Retrieve a cached CBOM document by scan ID.

    Returns None if not cached or Redis is unavailable.
    """
    if _redis_client is None:
        return None

    try:
        key = f"cbom:{scan_id}"
        data = await _redis_client.get(key)
        if data is not None:
            return json.loads(data)
    except Exception:
        logger.warning("Redis cache read failed for cbom:%s", scan_id, exc_info=True)

    return None


async def set_cached_cbom(scan_id: str, cbom_data: dict) -> None:
    """Store a CBOM document in cache with a 1-hour TTL.

    Silently fails if Redis is unavailable.
    """
    if _redis_client is None:
        return

    try:
        key = f"cbom:{scan_id}"
        await _redis_client.set(key, json.dumps(cbom_data), ex=CBOM_CACHE_TTL)
    except Exception:
        logger.warning("Redis cache write failed for cbom:%s", scan_id, exc_info=True)


async def check_redis_health() -> bool:
    """Check if Redis is reachable. Returns True if connected, False otherwise."""
    if _redis_client is None:
        return False

    try:
        await _redis_client.ping()
        return True
    except Exception:
        return False
