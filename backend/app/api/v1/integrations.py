"""Integration management endpoints — connect/disconnect git providers (ADR-014).

Provides OAuth connect + callback endpoints and integration listing for
GitHub, GitLab, and Bitbucket.
"""

import logging

from fastapi import APIRouter, HTTPException, status

from app.schemas.git_provider import (
    IntegrationListResponse,
    OAuthConnectRequest,
    OAuthConnectResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])

# ---------------------------------------------------------------------------
# Pluggable callbacks.
#
# The real implementation will persist integration records in the database
# and retrieve provider credentials from secure storage.  Tests can
# monkeypatch these.
# ---------------------------------------------------------------------------
_authenticate_provider = None  # async (provider: str, code: str) -> OAuthConnectResponse
_list_integrations = None  # async () -> IntegrationListResponse


def set_authenticate_provider(fn) -> None:  # noqa: ANN001
    """Register async callback ``(provider, code) -> OAuthConnectResponse``."""
    global _authenticate_provider  # noqa: PLW0603
    _authenticate_provider = fn


def set_list_integrations(fn) -> None:  # noqa: ANN001
    """Register async callback ``() -> IntegrationListResponse``."""
    global _list_integrations  # noqa: PLW0603
    _list_integrations = fn


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


@router.post("/github/connect", response_model=OAuthConnectResponse)
async def github_connect(body: OAuthConnectRequest) -> OAuthConnectResponse:
    """Initiate GitHub OAuth connection by exchanging the authorisation code."""
    if _authenticate_provider is not None:
        return await _authenticate_provider("github", body.code)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Integration backend not configured",
    )


@router.post("/github/callback", response_model=OAuthConnectResponse)
async def github_callback(body: OAuthConnectRequest) -> OAuthConnectResponse:
    """Handle the GitHub OAuth callback (code exchange)."""
    if _authenticate_provider is not None:
        return await _authenticate_provider("github", body.code)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Integration backend not configured",
    )


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------


@router.post("/gitlab/connect", response_model=OAuthConnectResponse)
async def gitlab_connect(body: OAuthConnectRequest) -> OAuthConnectResponse:
    """Initiate GitLab OAuth connection by exchanging the authorisation code."""
    if _authenticate_provider is not None:
        return await _authenticate_provider("gitlab", body.code)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Integration backend not configured",
    )


@router.post("/gitlab/callback", response_model=OAuthConnectResponse)
async def gitlab_callback(body: OAuthConnectRequest) -> OAuthConnectResponse:
    """Handle the GitLab OAuth callback (code exchange)."""
    if _authenticate_provider is not None:
        return await _authenticate_provider("gitlab", body.code)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Integration backend not configured",
    )


# ---------------------------------------------------------------------------
# Bitbucket
# ---------------------------------------------------------------------------


@router.post("/bitbucket/connect", response_model=OAuthConnectResponse)
async def bitbucket_connect(body: OAuthConnectRequest) -> OAuthConnectResponse:
    """Initiate Bitbucket OAuth connection by exchanging the authorisation code."""
    if _authenticate_provider is not None:
        return await _authenticate_provider("bitbucket", body.code)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Integration backend not configured",
    )


@router.post("/bitbucket/callback", response_model=OAuthConnectResponse)
async def bitbucket_callback(body: OAuthConnectRequest) -> OAuthConnectResponse:
    """Handle the Bitbucket OAuth callback (code exchange)."""
    if _authenticate_provider is not None:
        return await _authenticate_provider("bitbucket", body.code)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Integration backend not configured",
    )


# ---------------------------------------------------------------------------
# List connected integrations
# ---------------------------------------------------------------------------


@router.get("", response_model=IntegrationListResponse)
async def list_integrations() -> IntegrationListResponse:
    """List all connected git provider integrations."""
    if _list_integrations is not None:
        return await _list_integrations()

    # Return empty list if backend not configured yet.
    return IntegrationListResponse(items=[], total=0)
