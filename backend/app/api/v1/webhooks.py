"""Webhook receiver endpoints for GitHub, GitLab, and Bitbucket (ADR-014).

Each endpoint:
1. Validates the webhook signature / token
2. Extracts repo, branch, and commit info from the payload
3. Triggers a scan via the scan service

Webhook secrets are stored per-integration. For now a pluggable callback
is used so tests can run without a database.
"""

import json
import logging

from fastapi import APIRouter, HTTPException, Request, status

from app.schemas.git_provider import ProviderType, WebhookScanTrigger
from app.services.providers.bitbucket import BitbucketProvider
from app.services.providers.github import GitHubProvider
from app.services.providers.gitlab import GitLabProvider

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# ---------------------------------------------------------------------------
# Pluggable callbacks.
#
# The real implementation will look up webhook secrets from the database
# and dispatch scans via Taskiq.  Tests can monkeypatch these.
# ---------------------------------------------------------------------------
_get_webhook_secret = None  # async (provider: str, repo: str) -> str | None
_trigger_scan = None  # async (trigger: WebhookScanTrigger) -> None


def set_webhook_secret_lookup(fn) -> None:  # noqa: ANN001
    """Register async callback ``(provider, repo) -> secret | None``."""
    global _get_webhook_secret  # noqa: PLW0603
    _get_webhook_secret = fn


def set_scan_trigger(fn) -> None:  # noqa: ANN001
    """Register async callback ``(WebhookScanTrigger) -> None``."""
    global _trigger_scan  # noqa: PLW0603
    _trigger_scan = fn


# ---------------------------------------------------------------------------
# GitHub webhook
# ---------------------------------------------------------------------------


@router.post("/github")
async def github_webhook(request: Request) -> dict:
    """Receive and verify a GitHub webhook event."""
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()

    payload = json.loads(body)
    repo_full_name = payload.get("repository", {}).get("full_name", "")

    # Look up the secret for this repo.
    secret = None
    if _get_webhook_secret is not None:
        secret = await _get_webhook_secret("github", repo_full_name)
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No webhook secret configured for this repository",
        )

    # Verify signature — mandatory per ADR-014.
    provider = GitHubProvider(client_id="", client_secret="")
    if not await provider.verify_webhook_signature(body, signature, secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # Extract scan details.
    branch = ""
    commit_sha = ""
    ref = payload.get("ref", "")
    if ref.startswith("refs/heads/"):
        branch = ref.removeprefix("refs/heads/")
    head_commit = payload.get("head_commit")
    if head_commit is not None:
        commit_sha = head_commit.get("id", "")

    trigger = WebhookScanTrigger(
        provider=ProviderType.GITHUB,
        repo_full_name=repo_full_name,
        branch=branch,
        commit_sha=commit_sha,
        event_type=request.headers.get("X-GitHub-Event", "push"),
    )

    if _trigger_scan is not None:
        await _trigger_scan(trigger)

    logger.info("GitHub webhook processed: %s @ %s", repo_full_name, commit_sha[:8] if commit_sha else "?")
    return {"status": "accepted"}


# ---------------------------------------------------------------------------
# GitLab webhook
# ---------------------------------------------------------------------------


@router.post("/gitlab")
async def gitlab_webhook(request: Request) -> dict:
    """Receive and verify a GitLab webhook event."""
    token = request.headers.get("X-Gitlab-Token", "")
    body = await request.body()

    payload = json.loads(body)
    project = payload.get("project", {})
    repo_full_name = project.get("path_with_namespace", "")

    # Look up the secret for this repo.
    secret = None
    if _get_webhook_secret is not None:
        secret = await _get_webhook_secret("gitlab", repo_full_name)
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No webhook secret configured for this repository",
        )

    # Verify token — mandatory per ADR-014.
    provider = GitLabProvider(client_id="", client_secret="")
    if not await provider.verify_webhook_signature(b"", token, secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook token",
        )

    # Extract scan details.
    branch = ""
    commit_sha = ""
    ref = payload.get("ref", "")
    if ref.startswith("refs/heads/"):
        branch = ref.removeprefix("refs/heads/")
    elif "/" not in ref:
        branch = ref
    commits = payload.get("commits", [])
    if commits:
        commit_sha = commits[-1].get("id", "")
    elif payload.get("checkout_sha"):
        commit_sha = payload["checkout_sha"]

    trigger = WebhookScanTrigger(
        provider=ProviderType.GITLAB,
        repo_full_name=repo_full_name,
        branch=branch,
        commit_sha=commit_sha,
        event_type=payload.get("object_kind", "push"),
    )

    if _trigger_scan is not None:
        await _trigger_scan(trigger)

    logger.info("GitLab webhook processed: %s @ %s", repo_full_name, commit_sha[:8] if commit_sha else "?")
    return {"status": "accepted"}


# ---------------------------------------------------------------------------
# Bitbucket webhook
# ---------------------------------------------------------------------------


@router.post("/bitbucket")
async def bitbucket_webhook(request: Request) -> dict:
    """Receive and verify a Bitbucket webhook event."""
    signature = request.headers.get("X-Hub-Signature", "")
    body = await request.body()

    payload = json.loads(body)
    repo_data = payload.get("repository", {})
    repo_full_name = repo_data.get("full_name", "")

    # Look up the secret for this repo.
    secret = None
    if _get_webhook_secret is not None:
        secret = await _get_webhook_secret("bitbucket", repo_full_name)
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No webhook secret configured for this repository",
        )

    # Verify signature — mandatory per ADR-014.
    provider = BitbucketProvider(client_id="", client_secret="")
    if not await provider.verify_webhook_signature(body, signature, secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # Extract scan details from push payload.
    branch = ""
    commit_sha = ""
    push_data = payload.get("push", {})
    changes = push_data.get("changes", [])
    if changes:
        new = changes[0].get("new", {})
        branch = new.get("name", "")
        target = new.get("target", {})
        commit_sha = target.get("hash", "")

    trigger = WebhookScanTrigger(
        provider=ProviderType.BITBUCKET,
        repo_full_name=repo_full_name,
        branch=branch,
        commit_sha=commit_sha,
        event_type=request.headers.get("X-Event-Key", "repo:push"),
    )

    if _trigger_scan is not None:
        await _trigger_scan(trigger)

    logger.info("Bitbucket webhook processed: %s @ %s", repo_full_name, commit_sha[:8] if commit_sha else "?")
    return {"status": "accepted"}
