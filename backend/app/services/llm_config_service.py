"""LLM configuration service — manage per-org LLM provider settings (D5).

Provides CRUD for LLM configuration and connection testing.
"""

from __future__ import annotations

import uuid as _uuid
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models.llm_config import LLMConfig
from app.services.audit_service import audit_service
from app.services.llm.anthropic_provider import AnthropicProvider
from app.services.llm.openai_provider import OpenAIProvider

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

_SUPPORTED_PROVIDERS = {"anthropic", "openai", "ollama", "custom"}
_OA_ONLY_ROLES = {"org_admin"}


class LLMConfigService:
    """Manages per-org LLM provider configuration."""

    def _check_oa(self, actor: AuthenticatedUser) -> None:
        """Only Org Admin can manage LLM config."""
        if actor.role not in _OA_ONLY_ROLES:
            msg = f"Role '{actor.role}' is not permitted to manage LLM configuration"
            raise PermissionError(msg)

    async def _get_existing(
        self, org_id: str, session: AsyncSession
    ) -> LLMConfig | None:
        stmt = (
            select(LLMConfig)
            .where(LLMConfig.org_id == _uuid.UUID(org_id))
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_config(
        self,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict | None:
        """Get the current LLM configuration for the org."""
        cfg = await self._get_existing(actor.org_id, session)
        if cfg is None:
            return None

        return {
            "id": str(cfg.id),
            "provider": cfg.provider,
            "model": cfg.model,
            "endpoint_url": cfg.endpoint_url,
            "max_tokens": cfg.max_tokens,
            "temperature": cfg.temperature,
            "enabled": cfg.enabled,
            # Never expose api_key — only show prefix
            "api_key_set": bool(cfg.api_key_encrypted),
        }

    async def save_config(
        self,
        provider: str,
        model: str,
        api_key: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
        *,
        endpoint_url: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        enabled: bool = True,
    ) -> dict:
        """Create or update the LLM configuration."""
        self._check_oa(actor)

        if provider.lower() not in _SUPPORTED_PROVIDERS:
            msg = f"Unsupported LLM provider: {provider}. Supported: {', '.join(sorted(_SUPPORTED_PROVIDERS))}"
            raise ValueError(msg)

        existing = await self._get_existing(actor.org_id, session)

        if existing is not None:
            existing.provider = provider.lower()
            existing.model = model
            existing.api_key_encrypted = api_key  # Phase 4.5: raw storage
            existing.endpoint_url = endpoint_url
            existing.max_tokens = max_tokens
            existing.temperature = temperature
            existing.enabled = enabled
            await session.flush()
            cfg = existing
        else:
            cfg = LLMConfig(
                org_id=_uuid.UUID(actor.org_id),
                provider=provider.lower(),
                model=model,
                api_key_encrypted=api_key,
                endpoint_url=endpoint_url,
                max_tokens=max_tokens,
                temperature=temperature,
                enabled=enabled,
            )
            session.add(cfg)
            await session.flush()

        await audit_service.log(
            action_type="llm_config.updated",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="llm_config",
            resource_id=cfg.id,
            details={"provider": provider, "model": model},
            session=session,
        )

        return {
            "id": str(cfg.id),
            "provider": cfg.provider,
            "model": cfg.model,
            "endpoint_url": cfg.endpoint_url,
            "max_tokens": cfg.max_tokens,
            "temperature": cfg.temperature,
            "enabled": cfg.enabled,
            "api_key_set": True,
        }

    async def test_connection(
        self,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Test the configured LLM provider connection with a "Hello" prompt."""
        cfg = await self._get_existing(actor.org_id, session)
        if cfg is None:
            return {"ok": False, "error": "No LLM configuration found"}

        try:
            if cfg.provider == "anthropic":
                provider = AnthropicProvider(
                    api_key=cfg.api_key_encrypted,
                    model=cfg.model,
                )
            elif cfg.provider == "openai":
                provider = OpenAIProvider(
                    api_key=cfg.api_key_encrypted,
                    model=cfg.model,
                    base_url=cfg.endpoint_url,
                )
            elif cfg.provider == "ollama":
                from app.services.llm.ollama_provider import OllamaProvider

                provider = OllamaProvider(
                    base_url=cfg.endpoint_url or "http://localhost:11434",
                    model=cfg.model,
                )
            else:
                # Custom provider uses OpenAI-compatible endpoint
                provider = OpenAIProvider(
                    api_key=cfg.api_key_encrypted,
                    model=cfg.model,
                    base_url=cfg.endpoint_url,
                )

            ok = await provider.health_check()
            if ok:
                return {"ok": True, "provider": cfg.provider}
            return {"ok": False, "error": f"{cfg.provider} health check failed"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


llm_config_service = LLMConfigService()
