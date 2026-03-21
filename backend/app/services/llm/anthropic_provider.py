"""Anthropic (Claude) LLM provider for remediation generation (ADR-027)."""

import json
import logging

import anthropic

from app.services.llm.base import CodeContext, LLMProvider, RemediationResult
from app.services.llm.prompts import build_remediation_prompt

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    """LLM provider backed by the Anthropic Python SDK.

    Configuration is passed at construction time so the provider
    is stateless with respect to global config.
    """

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514") -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def generate_remediation(
        self, finding: dict, context: CodeContext
    ) -> RemediationResult:
        """Generate remediation using Claude."""
        prompt = build_remediation_prompt(finding, context)

        message = await self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_text = message.content[0].text

        # Parse JSON from the response — handle markdown fenced blocks
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            # Strip opening ```json or ``` and closing ```
            lines = cleaned.split("\n")
            lines = lines[1:]  # drop opening fence
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Anthropic response was not valid JSON: %s", raw_text[:200])
            data = {
                "original_code": context.code_snippet,
                "fixed_code": raw_text,
                "explanation": "LLM response could not be parsed as JSON.",
            }

        return RemediationResult(
            original_code=data.get("original_code", context.code_snippet),
            fixed_code=data.get("fixed_code", ""),
            explanation=data.get("explanation", ""),
            language=context.language,
            confidence=0.85,
            provider="anthropic",
        )

    async def health_check(self) -> bool:
        """Check Anthropic API reachability by listing models."""
        try:
            # A lightweight call to verify the API key works
            await self._client.messages.create(
                model=self._model,
                max_tokens=1,
                messages=[{"role": "user", "content": "ping"}],
            )
        except Exception:
            logger.warning("Anthropic health check failed", exc_info=True)
            return False
        return True
