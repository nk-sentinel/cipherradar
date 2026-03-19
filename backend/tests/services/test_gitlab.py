"""Tests for the GitLab provider — webhook token verification (ADR-014)."""

import pytest

from app.services.providers.gitlab import GitLabProvider


@pytest.fixture
def provider() -> GitLabProvider:
    """Create a GitLabProvider with dummy credentials."""
    return GitLabProvider(client_id="test-id", client_secret="test-secret")


# ---------------------------------------------------------------------------
# Webhook token verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_token_returns_true(provider: GitLabProvider) -> None:
    """The correct secret token should pass verification."""
    secret = "my-gitlab-token"
    # GitLab sends the token verbatim — no HMAC.
    result = await provider.verify_webhook_signature(b"", secret, secret)
    assert result is True


@pytest.mark.asyncio
async def test_invalid_token_returns_false(provider: GitLabProvider) -> None:
    """A wrong token should fail verification."""
    result = await provider.verify_webhook_signature(b"", "wrong-token", "correct-token")
    assert result is False


@pytest.mark.asyncio
async def test_empty_token_returns_false(provider: GitLabProvider) -> None:
    """An empty token should fail when secret is set."""
    result = await provider.verify_webhook_signature(b"", "", "my-secret")
    assert result is False


@pytest.mark.asyncio
async def test_both_empty_returns_true(provider: GitLabProvider) -> None:
    """Both empty should be considered equal (edge case — constant-time compare)."""
    result = await provider.verify_webhook_signature(b"", "", "")
    assert result is True
