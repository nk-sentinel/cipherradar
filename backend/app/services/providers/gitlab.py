"""GitLab provider implementation (ADR-014).

Supports GitLab Cloud and self-managed instances.
All HTTP calls go through ``httpx.AsyncClient`` with timeout.
"""

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

_TIMEOUT = httpx.Timeout(30.0)

# Map our status enum to GitLab commit status states.
_STATUS_MAP: dict[CheckStatus, str] = {
    CheckStatus.QUEUED: "pending",
    CheckStatus.IN_PROGRESS: "running",
    CheckStatus.COMPLETED: "success",
    CheckStatus.FAILED: "failed",
}


class GitLabProvider:
    """Git provider for GitLab Cloud and self-managed instances."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://gitlab.com",
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._api_url = f"{self._base_url}/api/v4"

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------

    async def authenticate(self, code: str) -> OAuthToken:
        """Exchange an OAuth authorisation code for a GitLab access token."""
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._base_url}/oauth/token",
                json={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": f"{self._base_url}/auth/callback",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuthToken(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scope", ""),
            refresh_token=data.get("refresh_token"),
        )

    # ------------------------------------------------------------------
    # Repositories (Projects)
    # ------------------------------------------------------------------

    async def list_repos(self, token: str) -> list[Repository]:
        """List projects the authenticated user has access to."""
        repos: list[Repository] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{self._api_url}/projects",
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "membership": "true",
                    "per_page": 100,
                    "order_by": "updated_at",
                },
            )
            resp.raise_for_status()

            for item in resp.json():
                repos.append(
                    Repository(
                        id=str(item["id"]),
                        full_name=item["path_with_namespace"],
                        clone_url=item["http_url_to_repo"],
                        default_branch=item.get("default_branch", "main"),
                    )
                )
        return repos

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    async def create_webhook(self, repo_id: str, url: str, secret: str) -> Webhook:
        """Register a webhook on a GitLab project.

        ``repo_id`` should be the numeric project ID or URL-encoded path.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._api_url}/projects/{repo_id}/hooks",
                json={
                    "url": url,
                    "token": secret,
                    "push_events": True,
                    "merge_requests_events": True,
                    "enable_ssl_verification": True,
                },
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        return Webhook(id=str(data["id"]), url=url, active=True)

    async def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify a GitLab webhook by comparing the ``X-Gitlab-Token`` header.

        GitLab does not use HMAC — it sends the configured secret token verbatim
        in the ``X-Gitlab-Token`` header.
        """
        return hmac.compare_digest(signature, secret)

    # ------------------------------------------------------------------
    # Commit status
    # ------------------------------------------------------------------

    async def post_check_status(
        self,
        repo_id: str,
        commit: str,
        status: CheckStatus,
        details: str,
    ) -> None:
        """Post a commit status on GitLab.

        ``repo_id`` should be the numeric project ID or URL-encoded path.
        """
        gl_state = _STATUS_MAP.get(status, "success")
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._api_url}/projects/{repo_id}/statuses/{commit}",
                json={
                    "state": gl_state,
                    "name": "CipherRadar CBOM Scan",
                    "description": details,
                },
            )
            resp.raise_for_status()

    # ------------------------------------------------------------------
    # Merge request notes (comments)
    # ------------------------------------------------------------------

    async def post_pr_comment(self, repo_id: str, pr_id: int, body: str) -> None:
        """Post a note (comment) on a GitLab merge request.

        ``repo_id`` should be the numeric project ID or URL-encoded path.
        ``pr_id`` is the merge request IID (not the global MR ID).
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._api_url}/projects/{repo_id}/merge_requests/{pr_id}/notes",
                json={"body": body},
            )
            resp.raise_for_status()
