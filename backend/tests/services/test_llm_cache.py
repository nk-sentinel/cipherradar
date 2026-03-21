"""Tests for remediation caching — cache hit/miss, TTL."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services.llm.base import RemediationResult
from app.services.llm.cache import (
    REMEDIATION_CACHE_TTL,
    _cache_key,
    get_cached_remediation,
    set_cached_remediation,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RESULT = RemediationResult(
    original_code="hashlib.md5(data).hexdigest()",
    fixed_code="hashlib.sha256(data).hexdigest()",
    explanation="MD5 is broken; SHA-256 is secure.",
    language="python",
    confidence=0.85,
    provider="anthropic",
)

RULE_ID = "cbom-python-md5-usage"
FILE_PATH = "auth/hash.py"
LINE = 12
CODE_SNIPPET = "hashlib.md5(data).hexdigest()"


# ---------------------------------------------------------------------------
# _cache_key
# ---------------------------------------------------------------------------


def test_cache_key_deterministic() -> None:
    """Same inputs should always produce the same cache key."""
    key1 = _cache_key(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)
    key2 = _cache_key(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)
    assert key1 == key2
    assert key1.startswith("remediation:")


def test_cache_key_different_code() -> None:
    """Different code should produce a different cache key."""
    key1 = _cache_key(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)
    key2 = _cache_key(RULE_ID, FILE_PATH, LINE, "different code")
    assert key1 != key2


# ---------------------------------------------------------------------------
# get_cached_remediation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_cached_remediation_miss() -> None:
    """Should return None when Redis has no cached entry."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("app.services.llm.cache.get_redis", return_value=mock_redis):
        result = await get_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)

    assert result is None


@pytest.mark.asyncio
async def test_get_cached_remediation_hit() -> None:
    """Should return a RemediationResult when Redis has a cached entry."""
    payload = {
        "original_code": SAMPLE_RESULT.original_code,
        "fixed_code": SAMPLE_RESULT.fixed_code,
        "explanation": SAMPLE_RESULT.explanation,
        "language": SAMPLE_RESULT.language,
        "confidence": SAMPLE_RESULT.confidence,
        "provider": SAMPLE_RESULT.provider,
    }
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(payload))

    with patch("app.services.llm.cache.get_redis", return_value=mock_redis):
        result = await get_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)

    assert result is not None
    assert isinstance(result, RemediationResult)
    assert result.fixed_code == SAMPLE_RESULT.fixed_code
    assert result.provider == "anthropic"


@pytest.mark.asyncio
async def test_get_cached_remediation_no_redis() -> None:
    """Should return None when Redis is not available."""
    with patch("app.services.llm.cache.get_redis", return_value=None):
        result = await get_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)

    assert result is None


@pytest.mark.asyncio
async def test_get_cached_remediation_redis_error() -> None:
    """Should return None gracefully when Redis raises."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=Exception("connection lost"))

    with patch("app.services.llm.cache.get_redis", return_value=mock_redis):
        result = await get_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET)

    assert result is None


# ---------------------------------------------------------------------------
# set_cached_remediation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_cached_remediation_stores_with_ttl() -> None:
    """Should store JSON payload in Redis with 7-day TTL."""
    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock()

    with patch("app.services.llm.cache.get_redis", return_value=mock_redis):
        await set_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET, SAMPLE_RESULT)

    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    # Verify the TTL is 7 days
    assert call_args.kwargs.get("ex") == REMEDIATION_CACHE_TTL
    assert REMEDIATION_CACHE_TTL == 7 * 24 * 3600

    # Verify the stored payload is valid JSON with expected fields
    stored_json = call_args.args[1]
    stored = json.loads(stored_json)
    assert stored["fixed_code"] == SAMPLE_RESULT.fixed_code
    assert stored["provider"] == "anthropic"


@pytest.mark.asyncio
async def test_set_cached_remediation_no_redis() -> None:
    """Should silently skip when Redis is not available."""
    with patch("app.services.llm.cache.get_redis", return_value=None):
        # Should not raise
        await set_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET, SAMPLE_RESULT)


@pytest.mark.asyncio
async def test_set_cached_remediation_redis_error() -> None:
    """Should silently handle Redis write errors."""
    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock(side_effect=Exception("connection lost"))

    with patch("app.services.llm.cache.get_redis", return_value=mock_redis):
        # Should not raise
        await set_cached_remediation(RULE_ID, FILE_PATH, LINE, CODE_SNIPPET, SAMPLE_RESULT)
