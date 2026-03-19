"""GitHub provider implementation (ADR-014).

Uses GitHub's REST API for OAuth, webhooks, Checks API, and issue comments.
All HTTP calls go through ``httpx.AsyncClient`` with timeout.
"""

import hashlib
import hmac
import logging

import httpx

from app.schemas.git_provider import (
    CheckStatus,
    OAuthToken,
    Repository,
    Webhook,
)

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_GITHUB_OAUTH = "https://github.com/login/oauth/access_token"
_TIMEOUT = httpx.Timeout(30.0)

# Map our status enum to GitHub Checks API conclusion/status values.
_STATUS_MAP: dict[CheckStatus, tuple[str, str | None]] = {
    CheckStatus.QUEUED: ("queued", None),
    CheckStatus.IN_PROGRESS: ("in_progress", None),
    CheckStatus.COMPLETED: ("completed", "success"),
    CheckStatus.FAILED: ("completed", "failure"),
}


class GitHubProvider:
    """Git provider for GitHub Cloud and GitHub Enterprise."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------

    async def authenticate(self, code: str) -> OAuthToken:
        """Exchange an OAuth authorisation code for a GitHub access token."""
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _GITHUB_OAUTH,
                json={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuthToken(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scope", ""),
        )

    # ------------------------------------------------------------------
    # Repositories
    # ------------------------------------------------------------------

    async def list_repos(self, token: str) -> list[Repository]:
        """List repositories the authenticated user has access to."""
        repos: list[Repository] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_GITHUB_API}/user/repos",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                params={"per_page": 100, "sort": "updated"},
            )
            resp.raise_for_status()

            for item in resp.json():
                repos.append(
                    Repository(
                        id=str(item["id"]),
                        full_name=item["full_name"],
                        clone_url=item["clone_url"],
                        default_branch=item.get("default_branch", "main"),
                    )
                )
        return repos

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    async def create_webhook(self, repo_id: str, url: str, secret: str) -> Webhook:
        """Register a push webhook on a GitHub repository.

        ``repo_id`` should be ``owner/repo``.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_GITHUB_API}/repos/{repo_id}/hooks",
                json={
                    "name": "web",
                    "active": True,
                    "events": ["push", "pull_request"],
                    "config": {
                        "url": url,
                        "content_type": "json",
                        "secret": secret,
                        "insecure_ssl": "0",
                    },
                },
                headers={
                    "Accept": "application/vnd.github+json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return Webhook(id=str(data["id"]), url=url, active=data.get("active", True))

    async def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify a GitHub webhook payload via HMAC-SHA256.

        GitHub sends the signature in the ``X-Hub-Signature-256`` header as
        ``sha256=<hex-digest>``.
        """
        if not signature.startswith("sha256="):
            return False
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        received = signature.removeprefix("sha256=")
        return hmac.compare_digest(expected, received)

    # ------------------------------------------------------------------
    # Checks API
    # ------------------------------------------------------------------

    async def post_check_status(
        self,
        repo_id: str,
        commit: str,
        status: CheckStatus,
        details: str,
    ) -> None:
        """Create a check run on a commit via the GitHub Checks API.

        ``repo_id`` should be ``owner/repo``.
        """
        gh_status, conclusion = _STATUS_MAP.get(status, ("completed", "neutral"))
        body: dict = {
            "name": "CipherRadar CBOM Scan",
            "head_sha": commit,
            "status": gh_status,
            "output": {
                "title": "CipherRadar CBOM Scan",
                "summary": details,
            },
        }
        if conclusion is not None:
            body["conclusion"] = conclusion

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_GITHUB_API}/repos/{repo_id}/check-runs",
                json=body,
                headers={"Accept": "application/vnd.github+json"},
            )
            resp.raise_for_status()

    # ------------------------------------------------------------------
    # PR comments
    # ------------------------------------------------------------------

    async def post_pr_comment(self, repo_id: str, pr_id: int, body: str) -> None:
        """Post a comment on a GitHub pull request (via the issues API).

        ``repo_id`` should be ``owner/repo``.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_GITHUB_API}/repos/{repo_id}/issues/{pr_id}/comments",
                json={"body": body},
                headers={"Accept": "application/vnd.github+json"},
            )
            resp.raise_for_status()
