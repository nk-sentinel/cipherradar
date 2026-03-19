"""Tests for the GitHub provider — webhook signature verification (ADR-014)."""

import hashlib
import hmac

import pytest

from app.services.providers.github import GitHubProvider


@pytest.fixture
def provider() -> GitHubProvider:
    """Create a GitHubProvider with dummy credentials."""
    return GitHubProvider(client_id="test-id", client_secret="test-secret")


# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_signature_returns_true(provider: GitHubProvider) -> None:
    """A correctly signed payload should pass verification."""
    secret = "my-webhook-secret"
    payload = b'{"action": "push", "ref": "refs/heads/main"}'
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    signature = f"sha256={digest}"

    result = await provider.verify_webhook_signature(payload, signature, secret)
    assert result is True


@pytest.mark.asyncio
async def test_invalid_signature_returns_false(provider: GitHubProvider) -> None:
    """A payload with a wrong signature should fail verification."""
    secret = "my-webhook-secret"
    payload = b'{"action": "push", "ref": "refs/heads/main"}'
    signature = "sha256=0000000000000000000000000000000000000000000000000000000000000000"

    result = await provider.verify_webhook_signature(payload, signature, secret)
    assert result is False


@pytest.mark.asyncio
async def test_missing_prefix_returns_false(provider: GitHubProvider) -> None:
    """A signature without the 'sha256=' prefix should fail."""
    secret = "my-webhook-secret"
    payload = b'{"action": "push"}'
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    result = await provider.verify_webhook_signature(payload, digest, secret)
    assert result is False


@pytest.mark.asyncio
async def test_empty_signature_returns_false(provider: GitHubProvider) -> None:
    """An empty signature string should fail verification."""
    result = await provider.verify_webhook_signature(b"payload", "", "secret")
    assert result is False


@pytest.mark.asyncio
async def test_tampered_payload_returns_false(provider: GitHubProvider) -> None:
    """A signature computed for a different payload should fail."""
    secret = "my-webhook-secret"
    original = b'{"original": true}'
    tampered = b'{"tampered": true}'
    digest = hmac.new(secret.encode(), original, hashlib.sha256).hexdigest()
    signature = f"sha256={digest}"

    result = await provider.verify_webhook_signature(tampered, signature, secret)
    assert result is False
