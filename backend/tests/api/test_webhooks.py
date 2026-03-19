"""Tests for the webhook receiver endpoints (ADR-014).

All external HTTP calls are avoided — we use the pluggable callbacks to
inject webhook secrets and capture scan triggers.
"""

import hashlib
import hmac
import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1 import webhooks
from app.main import create_app

if TYPE_CHECKING:
    from app.schemas.git_provider import WebhookScanTrigger

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    """Create a test app without lifespan."""
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    """Async HTTP client wired to the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture(autouse=True)
def _reset_callbacks():
    """Reset the pluggable webhook callbacks after each test."""
    original_secret = webhooks._get_webhook_secret
    original_trigger = webhooks._trigger_scan
    yield
    webhooks._get_webhook_secret = original_secret
    webhooks._trigger_scan = original_trigger


# ---------------------------------------------------------------------------
# GitHub webhook tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_github_webhook_valid_signature_triggers_scan(client: AsyncClient) -> None:
    """A GitHub webhook with a valid HMAC-SHA256 signature should trigger a scan."""
    secret = "gh-secret-123"
    payload = {
        "ref": "refs/heads/main",
        "head_commit": {"id": "abc1234567890"},
        "repository": {"full_name": "org/repo"},
    }
    body = json.dumps(payload).encode()
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    mock_secret_lookup = AsyncMock(return_value=secret)
    mock_trigger = AsyncMock()
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)
    webhooks.set_scan_trigger(mock_trigger)

    response = await client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": f"sha256={digest}",
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    mock_trigger.assert_awaited_once()
    trigger_arg: WebhookScanTrigger = mock_trigger.call_args[0][0]
    assert trigger_arg.provider == "github"
    assert trigger_arg.repo_full_name == "org/repo"
    assert trigger_arg.branch == "main"
    assert trigger_arg.commit_sha == "abc1234567890"


@pytest.mark.asyncio
async def test_github_webhook_invalid_signature_returns_401(client: AsyncClient) -> None:
    """A GitHub webhook with an invalid signature should be rejected."""
    secret = "gh-secret-123"
    payload = {"repository": {"full_name": "org/repo"}}
    body = json.dumps(payload).encode()

    mock_secret_lookup = AsyncMock(return_value=secret)
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)

    response = await client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": "sha256=invalid",
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401
    assert "signature" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_github_webhook_no_secret_returns_400(client: AsyncClient) -> None:
    """A GitHub webhook for an unconfigured repo should return 400."""
    payload = {"repository": {"full_name": "org/unknown"}}
    body = json.dumps(payload).encode()

    mock_secret_lookup = AsyncMock(return_value=None)
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)

    response = await client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": "sha256=whatever",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# GitLab webhook tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gitlab_webhook_valid_token_triggers_scan(client: AsyncClient) -> None:
    """A GitLab webhook with the correct token should trigger a scan."""
    secret = "gl-token-456"
    payload = {
        "ref": "refs/heads/develop",
        "commits": [{"id": "def7890abcdef"}],
        "project": {"path_with_namespace": "group/project"},
        "object_kind": "push",
    }
    body = json.dumps(payload).encode()

    mock_secret_lookup = AsyncMock(return_value=secret)
    mock_trigger = AsyncMock()
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)
    webhooks.set_scan_trigger(mock_trigger)

    response = await client.post(
        "/api/v1/webhooks/gitlab",
        content=body,
        headers={
            "X-Gitlab-Token": secret,
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    mock_trigger.assert_awaited_once()
    trigger_arg: WebhookScanTrigger = mock_trigger.call_args[0][0]
    assert trigger_arg.provider == "gitlab"
    assert trigger_arg.repo_full_name == "group/project"
    assert trigger_arg.branch == "develop"


@pytest.mark.asyncio
async def test_gitlab_webhook_invalid_token_returns_401(client: AsyncClient) -> None:
    """A GitLab webhook with a wrong token should be rejected."""
    secret = "gl-token-456"
    payload = {"project": {"path_with_namespace": "group/project"}}
    body = json.dumps(payload).encode()

    mock_secret_lookup = AsyncMock(return_value=secret)
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)

    response = await client.post(
        "/api/v1/webhooks/gitlab",
        content=body,
        headers={
            "X-Gitlab-Token": "wrong-token",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Bitbucket webhook tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bitbucket_webhook_valid_signature_triggers_scan(client: AsyncClient) -> None:
    """A Bitbucket webhook with a valid HMAC-SHA256 signature should trigger a scan."""
    secret = "bb-secret-789"
    payload = {
        "repository": {"full_name": "workspace/repo"},
        "push": {
            "changes": [
                {
                    "new": {
                        "name": "feature-branch",
                        "target": {"hash": "aabbccdd11223344"},
                    }
                }
            ]
        },
    }
    body = json.dumps(payload).encode()
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    mock_secret_lookup = AsyncMock(return_value=secret)
    mock_trigger = AsyncMock()
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)
    webhooks.set_scan_trigger(mock_trigger)

    response = await client.post(
        "/api/v1/webhooks/bitbucket",
        content=body,
        headers={
            "X-Hub-Signature": f"sha256={digest}",
            "X-Event-Key": "repo:push",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    mock_trigger.assert_awaited_once()
    trigger_arg: WebhookScanTrigger = mock_trigger.call_args[0][0]
    assert trigger_arg.provider == "bitbucket"
    assert trigger_arg.repo_full_name == "workspace/repo"
    assert trigger_arg.branch == "feature-branch"
    assert trigger_arg.commit_sha == "aabbccdd11223344"


@pytest.mark.asyncio
async def test_bitbucket_webhook_invalid_signature_returns_401(client: AsyncClient) -> None:
    """A Bitbucket webhook with an invalid signature should be rejected."""
    secret = "bb-secret-789"
    payload = {"repository": {"full_name": "workspace/repo"}}
    body = json.dumps(payload).encode()

    mock_secret_lookup = AsyncMock(return_value=secret)
    webhooks.set_webhook_secret_lookup(mock_secret_lookup)

    response = await client.post(
        "/api/v1/webhooks/bitbucket",
        content=body,
        headers={
            "X-Hub-Signature": "sha256=invalid",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401
