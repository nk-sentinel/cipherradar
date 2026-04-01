"""LLM provider factory — resolves provider name to concrete implementation (ADR-027)."""

from app.config import settings
from app.services.llm.base import LLMProvider


def create_llm_provider(provider_name: str | None = None) -> LLMProvider:
    """Create an LLM provider instance based on the provider name.

    Falls back to ``settings.llm_provider`` when *provider_name* is ``None``.

    Raises:
        ValueError: If the provider name is unknown or set to ``"none"``.
    """
    name = (provider_name or settings.llm_provider).lower().strip()

    if name == "anthropic":
        from app.services.llm.anthropic_provider import AnthropicProvider

        if not settings.llm_anthropic_api_key:
            msg = "CRADAR_LLM_ANTHROPIC_API_KEY is not configured"
            raise ValueError(msg)
        return AnthropicProvider(
            api_key=settings.llm_anthropic_api_key,
            model=settings.llm_anthropic_model,
        )

    if name == "openai":
        from app.services.llm.openai_provider import OpenAIProvider

        if not settings.llm_openai_api_key:
            msg = "CRADAR_LLM_OPENAI_API_KEY is not configured"
            raise ValueError(msg)
        return OpenAIProvider(
            api_key=settings.llm_openai_api_key,
            model=settings.llm_openai_model,
        )

    if name == "ollama":
        from app.services.llm.ollama_provider import OllamaProvider

        return OllamaProvider(
            base_url=settings.llm_ollama_url,
            model=settings.llm_ollama_model,
        )

    if name == "none":
        msg = "LLM provider is disabled (CRADAR_LLM_PROVIDER=none). Set a provider to use remediation."
        raise ValueError(msg)

    msg = f"Unknown LLM provider: {name!r}. Supported: anthropic, openai, ollama"
    raise ValueError(msg)
