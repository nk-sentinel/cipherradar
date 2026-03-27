"""Tests for integration management service (D3)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser
from app.models.integration_token import IntegrationToken
from app.services.integration_service import IntegrationService


_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()


def _make_actor(role: str = "org_admin") -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(_USER_ID),
        org_id=str(_ORG_ID),
        role=role,
        scopes=[],
    )


def _make_token(
    provider: str = "github",
    revoked: bool = False,
) -> MagicMock:
    tok = MagicMock(spec=IntegrationToken)
    tok.id = uuid.uuid4()
    tok.org_id = _ORG_ID
    tok.user_id = _USER_ID
    tok.provider = provider
    tok.token_encrypted = "ghp_test1234567890abcdef"
    tok.scope = "repo,read:org"
    tok.revoked_at = datetime.now(UTC) if revoked else None
    tok.expires_at = None
    tok.created_at = datetime.now(UTC)
    return tok


class TestConnect:
    """Test connecting a git provider with a PAT."""

    @pytest.mark.asyncio
    async def test_connect_stores_token(self) -> None:
        svc = IntegrationService()
        session = AsyncMock()

        actor = _make_actor()
        result = await svc.connect(
            provider="github",
            token="ghp_abc123456",
            actor=actor,
            session=session,
        )

        assert session.add.call_count >= 1
        added = session.add.call_args_list[0][0][0]
        assert isinstance(added, IntegrationToken)
        assert added.provider == "github"
        assert added.org_id == uuid.UUID(actor.org_id)
        assert result["provider"] == "github"
        assert result["status"] == "connected"

    @pytest.mark.asyncio
    async def test_connect_logs_audit(self) -> None:
        svc = IntegrationService()
        session = AsyncMock()
        actor = _make_actor()

        with patch("app.services.integration_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await svc.connect(
                provider="gitlab",
                token="glpat-test",
                actor=actor,
                session=session,
            )
            mock_audit.log.assert_awaited_once()
            call_kwargs = mock_audit.log.call_args.kwargs
            assert call_kwargs["action_type"] == "integration.connected"
            assert call_kwargs["resource_type"] == "integration"


class TestDisconnect:
    """Test disconnecting a git provider."""

    @pytest.mark.asyncio
    async def test_disconnect_revokes_token(self) -> None:
        svc = IntegrationService()
        token = _make_token()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = token
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        await svc.disconnect(
            provider="github",
            actor=actor,
            session=session,
        )

        assert token.revoked_at is not None

    @pytest.mark.asyncio
    async def test_disconnect_not_found_raises(self) -> None:
        svc = IntegrationService()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        with pytest.raises(ValueError, match="not found"):
            await svc.disconnect(
                provider="github",
                actor=actor,
                session=session,
            )


class TestTestConnection:
    """Test the test_connection method."""

    @pytest.mark.asyncio
    async def test_connection_success(self) -> None:
        svc = IntegrationService()
        token = _make_token(provider="github")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = token
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        with patch("app.services.integration_service.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await svc.test_connection(
                provider="github",
                actor=actor,
                session=session,
            )

        assert result["ok"] is True

    @pytest.mark.asyncio
    async def test_connection_failure(self) -> None:
        svc = IntegrationService()
        token = _make_token(provider="github")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = token
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        with patch("app.services.integration_service.httpx") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await svc.test_connection(
                provider="github",
                actor=actor,
                session=session,
            )

        assert result["ok"] is False


class TestDiscoverRepos:
    """Test repo discovery (mock for Phase 4.5)."""

    @pytest.mark.asyncio
    async def test_discover_returns_mock_repos(self) -> None:
        svc = IntegrationService()
        token = _make_token(provider="github")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = token
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        repos = await svc.discover_repos(
            provider="github",
            actor=actor,
            session=session,
        )

        assert isinstance(repos, list)
        assert len(repos) > 0
        assert "name" in repos[0]
        assert "url" in repos[0]


class TestImportRepos:
    """Test importing discovered repos as Project records."""

    @pytest.mark.asyncio
    async def test_import_creates_projects(self) -> None:
        svc = IntegrationService()
        session = AsyncMock()
        actor = _make_actor()

        # Mock group lookup
        mock_group_result = MagicMock()
        mock_group = MagicMock()
        mock_group.id = uuid.uuid4()
        mock_group.org_id = _ORG_ID
        mock_group_result.scalar_one_or_none.return_value = mock_group
        session.execute = AsyncMock(return_value=mock_group_result)

        repos_to_import = [
            {"name": "my-service", "url": "https://github.com/org/my-service"},
            {"name": "api-gateway", "url": "https://github.com/org/api-gateway"},
        ]

        with patch("app.services.integration_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.import_repos(
                repos=repos_to_import,
                group_id=mock_group.id,
                provider="github",
                actor=actor,
                session=session,
            )

        assert result["imported"] == 2


class TestRBAC:
    """Verify only OA and SM can use integration management."""

    @pytest.mark.asyncio
    async def test_developer_cannot_connect(self) -> None:
        """Developer role should be rejected."""
        svc = IntegrationService()
        session = AsyncMock()
        actor = _make_actor(role="developer")

        with pytest.raises(PermissionError):
            await svc.connect(
                provider="github",
                token="ghp_test",
                actor=actor,
                session=session,
            )
