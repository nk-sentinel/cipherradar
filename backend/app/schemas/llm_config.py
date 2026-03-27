"""Schemas for LLM configuration endpoints (D5)."""

from __future__ import annotations

from pydantic import Field

from app.schemas.base import CamelCaseModel


class LLMConfigResponse(CamelCaseModel):
    """Response representing the current LLM configuration."""

    id: str | None = None
    provider: str | None = None
    model: str | None = None
    endpoint_url: str | None = None
    max_tokens: int = 4096
    temperature: float = 0.0
    enabled: bool = False
    api_key_set: bool = False


class LLMConfigUpdateRequest(CamelCaseModel):
    """Request body to create or update LLM configuration."""

    provider: str = Field(..., description="LLM provider: anthropic, openai, ollama, custom")
    model: str = Field(..., description="Model name (e.g. claude-sonnet-4-20250514, gpt-4o)")
    api_key: str = Field(..., description="API key for the provider")
    endpoint_url: str | None = Field(default=None, description="Custom endpoint URL (for ollama/custom)")
    max_tokens: int = Field(default=4096, ge=1, le=128000)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    enabled: bool = True


class LLMTestResponse(CamelCaseModel):
    """Response from testing the LLM connection."""

    ok: bool
    provider: str | None = None
    error: str | None = None
