"""Ollama (local) LLM provider for air-gapped remediation (ADR-027)."""

import json
import logging

import httpx

from app.services.llm.base import CodeContext, LLMProvider, RemediationResult
from app.services.llm.prompts import build_remediation_prompt

logger = logging.getLogger(__name__)


class OllamaProvider(LLMProvider):
    """LLM provider that calls a local Ollama instance over HTTP.

    Designed for air-gapped enterprise deployments where no external
    API calls are permitted.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "codellama",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    async def generate_remediation(
        self, finding: dict, context: CodeContext
    ) -> RemediationResult:
        """Generate remediation using a local Ollama model."""
        prompt = build_remediation_prompt(finding, context)

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self._base_url}/api/generate",
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            response.raise_for_status()
            body = response.json()

        raw_text = body.get("response", "")

        # Parse JSON from the response
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
            logger.warning("Ollama response was not valid JSON: %s", raw_text[:200])
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
            confidence=0.65,
            provider="ollama",
        )

    async def health_check(self) -> bool:
        """Check if the local Ollama instance is running."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self._base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            logger.warning("Ollama health check failed", exc_info=True)
            return False
