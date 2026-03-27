"""Tests for LLM configuration service (D5)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser
from app.models.llm_config import LLMConfig
from app.services.llm_config_service import LLMConfigService


_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()


def _make_actor(role: str = "org_admin") -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(_USER_ID),
        org_id=str(_ORG_ID),
        role=role,
        scopes=[],
    )


def _make_config(
    provider: str = "anthropic",
    enabled: bool = True,
) -> MagicMock:
    cfg = MagicMock(spec=LLMConfig)
    cfg.id = uuid.uuid4()
    cfg.org_id = _ORG_ID
    cfg.provider = provider
    cfg.model = "claude-sonnet-4-20250514"
    cfg.api_key_encrypted = "sk-ant-test123"
    cfg.endpoint_url = None
    cfg.max_tokens = 4096
    cfg.temperature = 0.0
    cfg.enabled = enabled
    return cfg


class TestGetConfig:
    """Test reading LLM configuration."""

    @pytest.mark.asyncio
    async def test_get_config_returns_existing(self) -> None:
        svc = LLMConfigService()
        cfg = _make_config()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = cfg
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        result = await svc.get_config(actor=actor, session=session)

        assert result is not None
        assert result["provider"] == "anthropic"
        assert result["model"] == "claude-sonnet-4-20250514"

    @pytest.mark.asyncio
    async def test_get_config_returns_none_when_empty(self) -> None:
        svc = LLMConfigService()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        result = await svc.get_config(actor=actor, session=session)
        assert result is None


class TestSaveConfig:
    """Test saving LLM configuration."""

    @pytest.mark.asyncio
    async def test_save_config_creates_new(self) -> None:
        svc = LLMConfigService()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        with patch("app.services.llm_config_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.save_config(
                provider="openai",
                model="gpt-4o",
                api_key="sk-test123",
                actor=actor,
                session=session,
            )

        session.add.assert_called_once()
        assert result["provider"] == "openai"

    @pytest.mark.asyncio
    async def test_save_config_updates_existing(self) -> None:
        svc = LLMConfigService()
        existing = _make_config(provider="anthropic")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        with patch("app.services.llm_config_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            result = await svc.save_config(
                provider="openai",
                model="gpt-4o",
                api_key="sk-new-key",
                actor=actor,
                session=session,
            )

        assert existing.provider == "openai"
        assert existing.model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_save_config_invalid_provider(self) -> None:
        svc = LLMConfigService()
        session = AsyncMock()
        actor = _make_actor()

        with pytest.raises(ValueError, match="Unsupported"):
            await svc.save_config(
                provider="invalid",
                model="something",
                api_key="key",
                actor=actor,
                session=session,
            )


class TestTestConnection:
    """Test the LLM connection test method."""

    @pytest.mark.asyncio
    async def test_connection_anthropic_success(self) -> None:
        svc = LLMConfigService()
        cfg = _make_config(provider="anthropic")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = cfg
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        with patch("app.services.llm_config_service.AnthropicProvider") as mock_cls:
            mock_provider = AsyncMock()
            mock_provider.health_check = AsyncMock(return_value=True)
            mock_cls.return_value = mock_provider

            result = await svc.test_connection(actor=actor, session=session)

        assert result["ok"] is True
        assert result["provider"] == "anthropic"

    @pytest.mark.asyncio
    async def test_connection_no_config(self) -> None:
        svc = LLMConfigService()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        actor = _make_actor()
        result = await svc.test_connection(actor=actor, session=session)
        assert result["ok"] is False


class TestRBAC:
    """Verify only OA can manage LLM config."""

    @pytest.mark.asyncio
    async def test_non_oa_cannot_save(self) -> None:
        svc = LLMConfigService()
        session = AsyncMock()
        actor = _make_actor(role="security_manager")

        with pytest.raises(PermissionError):
            await svc.save_config(
                provider="anthropic",
                model="test",
                api_key="key",
                actor=actor,
                session=session,
            )
