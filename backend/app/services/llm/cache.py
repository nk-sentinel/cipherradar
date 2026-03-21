"""Remediation result caching — Redis-backed with 7-day TTL (ADR-027).

Cache key is derived from the finding fingerprint: rule_id + file + line + code_hash.
Identical findings produce the same cache key, eliminating redundant LLM calls.
"""

import hashlib
import json
import logging
from typing import TYPE_CHECKING

from app.services.cache_service import get_redis
from app.services.llm.base import RemediationResult

if TYPE_CHECKING:
    import redis.asyncio as redis

logger = logging.getLogger(__name__)

# 7 days in seconds
REMEDIATION_CACHE_TTL = 7 * 24 * 3600


def _cache_key(rule_id: str, file_path: str, line: int, code_snippet: str) -> str:
    """Build a deterministic cache key from finding fingerprint components."""
    code_hash = hashlib.sha256(code_snippet.encode()).hexdigest()[:16]
    return f"remediation:{rule_id}:{file_path}:{line}:{code_hash}"


async def get_cached_remediation(
    rule_id: str,
    file_path: str,
    line: int,
    code_snippet: str,
) -> RemediationResult | None:
    """Retrieve a cached remediation result, or None if not cached.

    Returns None silently if Redis is unavailable.
    """
    client: redis.Redis | None = get_redis()
    if client is None:
        return None

    key = _cache_key(rule_id, file_path, line, code_snippet)
    try:
        data = await client.get(key)
        if data is None:
            return None
        payload = json.loads(data)
        return RemediationResult(**payload)
    except Exception:
        logger.warning("Redis cache read failed for %s", key, exc_info=True)
        return None


async def set_cached_remediation(
    rule_id: str,
    file_path: str,
    line: int,
    code_snippet: str,
    result: RemediationResult,
) -> None:
    """Store a remediation result in Redis with 7-day TTL.

    Silently fails if Redis is unavailable.
    """
    client: redis.Redis | None = get_redis()
    if client is None:
        return

    key = _cache_key(rule_id, file_path, line, code_snippet)
    payload = {
        "original_code": result.original_code,
        "fixed_code": result.fixed_code,
        "explanation": result.explanation,
        "language": result.language,
        "confidence": result.confidence,
        "provider": result.provider,
    }
    try:
        await client.set(key, json.dumps(payload), ex=REMEDIATION_CACHE_TTL)
    except Exception:
        logger.warning("Redis cache write failed for %s", key, exc_info=True)
