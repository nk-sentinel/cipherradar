"""Bitbucket provider implementation (ADR-014).

Supports Bitbucket Cloud (OAuth 2.0) and Bitbucket Data Center (PAT auth).
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

_TIMEOUT = httpx.Timeout(30.0)

# Bitbucket Cloud API base.
_BB_CLOUD_API = "https://api.bitbucket.org/2.0"
_BB_CLOUD_AUTH = "https://bitbucket.org/site/oauth2/access_token"

# Map our status enum to Bitbucket build status states.
_STATUS_MAP: dict[CheckStatus, str] = {
    CheckStatus.QUEUED: "INPROGRESS",
    CheckStatus.IN_PROGRESS: "INPROGRESS",
    CheckStatus.COMPLETED: "SUCCESSFUL",
    CheckStatus.FAILED: "FAILED",
}


class BitbucketProvider:
    """Git provider for Bitbucket Cloud.

    For Bitbucket Data Center, supply a ``base_url`` pointing to the
    server's REST API and use PAT-based authentication.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        base_url: str | None = None,
        is_data_center: bool = False,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._is_data_center = is_data_center
        if base_url is not None:
            self._api_url = base_url.rstrip("/")
        else:
            self._api_url = _BB_CLOUD_API

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------

    async def authenticate(self, code: str) -> OAuthToken:
        """Exchange an OAuth authorisation code for a Bitbucket access token.

        For Data Center, this would typically use a Personal Access Token
        (PAT) instead.  The ``code`` parameter carries the PAT in that case.
        """
        if self._is_data_center:
            # Data Center uses PATs directly.
            return OAuthToken(access_token=code, token_type="bearer")

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _BB_CLOUD_AUTH,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                },
                auth=(self._client_id, self._client_secret),
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuthToken(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scopes", ""),
            refresh_token=data.get("refresh_token"),
        )

    # ------------------------------------------------------------------
    # Repositories
    # ------------------------------------------------------------------

    async def list_repos(self, token: str) -> list[Repository]:
        """List repositories the authenticated user has access to."""
        repos: list[Repository] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{self._api_url}/repositories",
                headers={"Authorization": f"Bearer {token}"},
                params={"role": "member", "pagelen": 100},
            )
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("values", []):
                clone_links = {link["name"]: link["href"] for link in item.get("links", {}).get("clone", [])}
                repos.append(
                    Repository(
                        id=item["uuid"],
                        full_name=item["full_name"],
                        clone_url=clone_links.get("https", clone_links.get("ssh", "")),
                        default_branch=item.get("mainbranch", {}).get("name", "main"),
                    )
                )
        return repos

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    async def create_webhook(self, repo_id: str, url: str, secret: str) -> Webhook:
        """Register a webhook on a Bitbucket repository.

        ``repo_id`` should be ``workspace/repo_slug``.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._api_url}/repositories/{repo_id}/hooks",
                json={
                    "description": "CipherRadar CBOM webhook",
                    "url": url,
                    "active": True,
                    "events": ["repo:push", "pullrequest:created", "pullrequest:updated"],
                    "secret": secret,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return Webhook(id=data["uuid"], url=url, active=data.get("active", True))

    async def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify a Bitbucket webhook payload via HMAC-SHA256.

        Bitbucket sends the signature in the ``X-Hub-Signature`` header as
        ``sha256=<hex-digest>``.
        """
        if not signature.startswith("sha256="):
            return False
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        received = signature.removeprefix("sha256=")
        return hmac.compare_digest(expected, received)

    # ------------------------------------------------------------------
    # Build status
    # ------------------------------------------------------------------

    async def post_check_status(
        self,
        repo_id: str,
        commit: str,
        status: CheckStatus,
        details: str,
    ) -> None:
        """Post a build status on a Bitbucket commit.

        ``repo_id`` should be ``workspace/repo_slug``.
        """
        bb_state = _STATUS_MAP.get(status, "SUCCESSFUL")
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._api_url}/repositories/{repo_id}/commit/{commit}/statuses/build",
                json={
                    "state": bb_state,
                    "key": "cipherradar-cbom-scan",
                    "name": "CipherRadar CBOM Scan",
                    "description": details,
                    "url": "",
                },
            )
            resp.raise_for_status()

    # ------------------------------------------------------------------
    # PR comments
    # ------------------------------------------------------------------

    async def post_pr_comment(self, repo_id: str, pr_id: int, body: str) -> None:
        """Post a comment on a Bitbucket pull request.

        ``repo_id`` should be ``workspace/repo_slug``.
        """
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{self._api_url}/repositories/{repo_id}/pullrequests/{pr_id}/comments",
                json={"content": {"raw": body}},
            )
            resp.raise_for_status()
