"""GitProvider protocol — common interface for GitHub/GitLab/Bitbucket (ADR-014).

All provider-specific implementations must satisfy this protocol. Business logic
only depends on the protocol, never on concrete provider classes.
"""

from typing import Protocol, runtime_checkable

from app.schemas.git_provider import (
    CheckStatus,
    OAuthToken,
    Repository,
    Webhook,
)


@runtime_checkable
class GitProvider(Protocol):
    """Async interface that every git provider implementation must satisfy."""

    async def authenticate(self, code: str) -> OAuthToken:
        """Exchange an OAuth authorisation code for an access token."""
        ...

    async def list_repos(self, token: str) -> list[Repository]:
        """List repositories accessible with the given token."""
        ...

    async def create_webhook(self, repo_id: str, url: str, secret: str) -> Webhook:
        """Register a webhook on the remote repository."""
        ...

    async def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify that an incoming webhook payload is authentic.

        Returns True if the signature is valid, False otherwise.
        This check is **mandatory** — unsigned or unverified payloads must be rejected.
        """
        ...

    async def post_check_status(
        self,
        repo_id: str,
        commit: str,
        status: CheckStatus,
        details: str,
    ) -> None:
        """Post a commit check / build status to the provider."""
        ...

    async def post_pr_comment(self, repo_id: str, pr_id: int, body: str) -> None:
        """Post a comment on a pull request / merge request."""
        ...
