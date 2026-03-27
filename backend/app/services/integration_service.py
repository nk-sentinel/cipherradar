"""Integration management service — connect/disconnect git providers (D3).

Provides PAT-based connection, disconnection, connection testing,
repo discovery (mock for Phase 4.5), and repo import.
"""

from __future__ import annotations

import hashlib
import uuid as _uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
from sqlalchemy import select

from app.models.integration_token import IntegrationToken
from app.models.project import Project
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

# Providers and their API endpoints for testing connectivity
_PROVIDER_TEST_URLS: dict[str, str] = {
    "github": "https://api.github.com/user",
    "gitlab": "https://gitlab.com/api/v4/user",
    "bitbucket": "https://api.bitbucket.org/2.0/user",
}

_ALLOWED_ROLES = {"org_admin", "security_manager"}

# Mock repo data for Phase 4.5 discovery
_MOCK_REPOS: dict[str, list[dict[str, str]]] = {
    "github": [
        {"name": "payment-service", "url": "https://github.com/nk-sentinel/payment-service", "default_branch": "main"},
        {"name": "auth-api", "url": "https://github.com/nk-sentinel/auth-api", "default_branch": "main"},
        {"name": "data-pipeline", "url": "https://github.com/nk-sentinel/data-pipeline", "default_branch": "develop"},
    ],
    "gitlab": [
        {"name": "crypto-lib", "url": "https://gitlab.com/nk-sentinel/crypto-lib", "default_branch": "main"},
        {"name": "cert-manager", "url": "https://gitlab.com/nk-sentinel/cert-manager", "default_branch": "main"},
    ],
    "bitbucket": [
        {"name": "legacy-app", "url": "https://bitbucket.org/nk-sentinel/legacy-app", "default_branch": "master"},
    ],
}


class IntegrationService:
    """Manages git provider integrations for an organisation."""

    def _check_role(self, actor: AuthenticatedUser) -> None:
        """Verify the actor has OA or SM role."""
        if actor.role not in _ALLOWED_ROLES:
            msg = f"Role '{actor.role}' is not permitted for integration management"
            raise PermissionError(msg)

    async def connect(
        self,
        provider: str,
        token: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Store a PAT for a git provider integration.

        Phase 4.5: stores raw token. Encryption deferred to production hardening.
        """
        self._check_role(actor)

        provider = provider.lower()
        if provider not in _PROVIDER_TEST_URLS:
            msg = f"Unsupported provider: {provider}"
            raise ValueError(msg)

        token_prefix = token[:8] + "..." if len(token) > 8 else token

        integration = IntegrationToken(
            org_id=_uuid.UUID(actor.org_id),
            user_id=_uuid.UUID(actor.user_id),
            provider=provider,
            token_encrypted=token,  # Phase 4.5: raw storage
            scope=None,
            expires_at=None,
        )
        session.add(integration)
        await session.flush()

        await audit_service.log(
            action_type="integration.connected",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="integration",
            resource_id=integration.id,
            details={"provider": provider, "token_prefix": token_prefix},
            session=session,
        )

        return {
            "id": str(integration.id),
            "provider": provider,
            "status": "connected",
            "connected_at": datetime.now(UTC).isoformat(),
        }

    async def disconnect(
        self,
        provider: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Revoke the integration token for a provider."""
        self._check_role(actor)

        stmt = (
            select(IntegrationToken)
            .where(
                IntegrationToken.org_id == _uuid.UUID(actor.org_id),
                IntegrationToken.provider == provider.lower(),
                IntegrationToken.revoked_at.is_(None),
            )
            .order_by(IntegrationToken.created_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        token = result.scalar_one_or_none()

        if token is None:
            msg = f"Integration for provider '{provider}' not found"
            raise ValueError(msg)

        token.revoked_at = datetime.now(UTC)
        await session.flush()

        await audit_service.log(
            action_type="integration.disconnected",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="integration",
            resource_id=token.id,
            details={"provider": provider},
            session=session,
        )

        return {"provider": provider, "status": "disconnected"}

    async def test_connection(
        self,
        provider: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Test connectivity to a provider API using stored token."""
        self._check_role(actor)

        stmt = (
            select(IntegrationToken)
            .where(
                IntegrationToken.org_id == _uuid.UUID(actor.org_id),
                IntegrationToken.provider == provider.lower(),
                IntegrationToken.revoked_at.is_(None),
            )
            .order_by(IntegrationToken.created_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        token = result.scalar_one_or_none()

        if token is None:
            return {"ok": False, "error": f"No active token for '{provider}'"}

        test_url = _PROVIDER_TEST_URLS.get(provider.lower())
        if not test_url:
            return {"ok": False, "error": f"Unknown provider '{provider}'"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    test_url,
                    headers={"Authorization": f"Bearer {token.token_encrypted}"},
                )
            if resp.status_code == 200:
                return {"ok": True, "provider": provider}
            return {"ok": False, "error": f"Provider returned {resp.status_code}"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}

    async def discover_repos(
        self,
        provider: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> list[dict]:
        """Discover repositories from a connected provider.

        Phase 4.5: returns mock data. Real API calls deferred to Phase 5.
        """
        self._check_role(actor)

        # Verify token exists
        stmt = (
            select(IntegrationToken)
            .where(
                IntegrationToken.org_id == _uuid.UUID(actor.org_id),
                IntegrationToken.provider == provider.lower(),
                IntegrationToken.revoked_at.is_(None),
            )
            .limit(1)
        )
        result = await session.execute(stmt)
        token = result.scalar_one_or_none()

        if token is None:
            msg = f"No active integration for '{provider}'"
            raise ValueError(msg)

        return _MOCK_REPOS.get(provider.lower(), [])

    async def import_repos(
        self,
        repos: list[dict],
        group_id: _uuid.UUID,
        provider: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Import discovered repos as Project records."""
        self._check_role(actor)

        imported = 0
        for repo in repos:
            project = Project(
                group_id=group_id,
                org_id=_uuid.UUID(actor.org_id),
                name=repo["name"],
                git_url=repo.get("url"),
                provider=provider.lower(),
            )
            session.add(project)
            imported += 1

        await session.flush()

        await audit_service.log(
            action_type="integration.repos_imported",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="integration",
            details={"provider": provider, "count": imported, "repos": [r["name"] for r in repos]},
            session=session,
        )

        return {"imported": imported, "provider": provider}


integration_service = IntegrationService()
