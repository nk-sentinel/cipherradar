"""Provider factory — resolves a ProviderType to its concrete implementation (ADR-014)."""

from app.schemas.git_provider import ProviderType
from app.services.git_provider import GitProvider
from app.services.providers.bitbucket import BitbucketProvider
from app.services.providers.github import GitHubProvider
from app.services.providers.gitlab import GitLabProvider


def get_provider(
    provider_type: ProviderType,
    client_id: str,
    client_secret: str,
    *,
    base_url: str | None = None,
) -> GitProvider:
    """Return a concrete GitProvider for the given provider type.

    Raises ``ValueError`` if the provider type is unknown.
    """
    if provider_type == ProviderType.GITHUB:
        return GitHubProvider(client_id=client_id, client_secret=client_secret)
    if provider_type == ProviderType.GITLAB:
        return GitLabProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url or "https://gitlab.com",
        )
    if provider_type == ProviderType.BITBUCKET:
        return BitbucketProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
    msg = f"Unknown provider type: {provider_type}"
    raise ValueError(msg)
