"""OpenAI LLM provider for remediation generation (ADR-027)."""

import json
import logging

import openai

from app.services.llm.base import CodeContext, LLMProvider, RemediationResult
from app.services.llm.prompts import build_remediation_prompt

logger = logging.getLogger(__name__)


class OpenAIProvider(LLMProvider):
    """LLM provider backed by the OpenAI Python SDK.

    Supports any OpenAI-compatible API (including Azure OpenAI) by
    accepting an optional ``base_url`` override.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str | None = None,
    ) -> None:
        kwargs: dict = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = openai.AsyncOpenAI(**kwargs)
        self._model = model

    async def generate_remediation(
        self, finding: dict, context: CodeContext
    ) -> RemediationResult:
        """Generate remediation using OpenAI."""
        prompt = build_remediation_prompt(finding, context)

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cryptography security expert. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=2048,
            temperature=0.2,
        )

        raw_text = response.choices[0].message.content or ""

        # Parse JSON from the response — handle markdown fenced blocks
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("OpenAI response was not valid JSON: %s", raw_text[:200])
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
            confidence=0.80,
            provider="openai",
        )

    async def health_check(self) -> bool:
        """Check OpenAI API reachability."""
        try:
            await self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
            )
        except Exception:
            logger.warning("OpenAI health check failed", exc_info=True)
            return False
        return True
