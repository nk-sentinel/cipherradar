"""Tests for the Anthropic LLM provider — mock SDK, verify remediation generation."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.llm.anthropic_provider import AnthropicProvider
from app.services.llm.base import CodeContext, RemediationResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_FINDING = {
    "rule_id": "cbom-python-md5-usage",
    "name": "MD5 hash function",
    "severity": "high",
    "algorithm": "MD5",
    "quantum_status": "broken",
}

SAMPLE_CONTEXT = CodeContext(
    language="python",
    file_path="auth/hash.py",
    code_snippet="import hashlib\ndigest = hashlib.md5(data).hexdigest()",
    line_number=12,
    library="hashlib",
)

GOOD_LLM_RESPONSE = json.dumps(
    {
        "original_code": "import hashlib\ndigest = hashlib.md5(data).hexdigest()",
        "fixed_code": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()",
        "explanation": "MD5 is cryptographically broken. SHA-256 is a secure replacement.",
    }
)


@pytest.fixture
def provider() -> AnthropicProvider:
    """Create an AnthropicProvider with a dummy API key."""
    return AnthropicProvider(api_key="test-key-123", model="claude-sonnet-4-20250514")


# ---------------------------------------------------------------------------
# generate_remediation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_remediation_success(provider: AnthropicProvider) -> None:
    """Should parse a valid JSON response and return a RemediationResult."""
    mock_message = MagicMock()
    mock_content = MagicMock()
    mock_content.text = GOOD_LLM_RESPONSE
    mock_message.content = [mock_content]

    provider._client.messages.create = AsyncMock(return_value=mock_message)

    result = await provider.generate_remediation(SAMPLE_FINDING, SAMPLE_CONTEXT)

    assert isinstance(result, RemediationResult)
    assert result.provider == "anthropic"
    assert result.language == "python"
    assert "sha256" in result.fixed_code.lower()
    assert result.confidence == 0.85
    assert result.original_code == SAMPLE_CONTEXT.code_snippet


@pytest.mark.asyncio
async def test_generate_remediation_markdown_fenced(provider: AnthropicProvider) -> None:
    """Should handle markdown-fenced JSON responses."""
    fenced = f"```json\n{GOOD_LLM_RESPONSE}\n```"
    mock_message = MagicMock()
    mock_content = MagicMock()
    mock_content.text = fenced
    mock_message.content = [mock_content]

    provider._client.messages.create = AsyncMock(return_value=mock_message)

    result = await provider.generate_remediation(SAMPLE_FINDING, SAMPLE_CONTEXT)

    assert isinstance(result, RemediationResult)
    assert "sha256" in result.fixed_code.lower()


@pytest.mark.asyncio
async def test_generate_remediation_invalid_json(provider: AnthropicProvider) -> None:
    """Should gracefully handle non-JSON responses."""
    mock_message = MagicMock()
    mock_content = MagicMock()
    mock_content.text = "Here is the fix: use SHA-256 instead of MD5"
    mock_message.content = [mock_content]

    provider._client.messages.create = AsyncMock(return_value=mock_message)

    result = await provider.generate_remediation(SAMPLE_FINDING, SAMPLE_CONTEXT)

    assert isinstance(result, RemediationResult)
    assert result.provider == "anthropic"
    # Falls back to raw text
    assert "SHA-256" in result.fixed_code


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_check_success(provider: AnthropicProvider) -> None:
    """health_check should return True when API responds."""
    mock_message = MagicMock()
    mock_content = MagicMock()
    mock_content.text = "pong"
    mock_message.content = [mock_content]

    provider._client.messages.create = AsyncMock(return_value=mock_message)

    assert await provider.health_check() is True


@pytest.mark.asyncio
async def test_health_check_failure(provider: AnthropicProvider) -> None:
    """health_check should return False when API raises."""
    provider._client.messages.create = AsyncMock(side_effect=Exception("connection refused"))

    assert await provider.health_check() is False
