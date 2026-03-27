"""Remediation service — LLM-assisted code fix generation with privacy transforms (D5).

Loads LLM config from database, builds prompts with finding context,
calls the configured provider, and caches responses.
"""

from __future__ import annotations

import hashlib
import re
import uuid as _uuid
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models.llm_config import LLMConfig
from app.services.llm.base import CodeContext, RemediationResult
from app.services.llm.cache import get_cached_remediation, set_cached_remediation
from app.services.llm.prompts import build_remediation_prompt

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser
    from app.models.finding import Finding


def _strip_comments(code: str, language: str) -> str:
    """Remove comments from code to reduce sensitive information leakage."""
    if language in ("python", "ruby", "yaml", "shell", "bash"):
        # Remove # line comments (but not #! shebang)
        return re.sub(r"(?<!^#!)#[^\n]*", "", code)
    if language in ("java", "go", "javascript", "typescript", "c", "cpp", "rust", "kotlin", "swift"):
        # Remove // line comments
        code = re.sub(r"//[^\n]*", "", code)
        # Remove /* block comments */
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        return code
    return code


def _anonymize_variables(code: str) -> str:
    """Replace variable names with generic placeholders.

    A simple heuristic: replace camelCase/snake_case identifiers that look
    like custom variable names (not keywords).
    """
    # Replace strings that look like internal identifiers
    # e.g., companySecretKey -> VAR_1, internal_token -> VAR_2
    counter = 0
    seen: dict[str, str] = {}

    def _replace(match: re.Match) -> str:
        nonlocal counter
        word = match.group(0)
        if word not in seen:
            counter += 1
            seen[word] = f"VAR_{counter}"
        return seen[word]

    # Only replace identifiers that contain underscores or mixed case
    # (suggesting they're custom names, not language keywords)
    return re.sub(
        r"\b[a-z][a-zA-Z]*(?:_[a-zA-Z]+)+\b|\b[a-z]+[A-Z][a-zA-Z]*\b",
        _replace,
        code,
    )


class RemediationService:
    """Generates LLM-assisted remediation suggestions using configured provider."""

    async def _get_llm_config(self, org_id: str, session: AsyncSession) -> LLMConfig | None:
        """Load org's LLM config from database."""
        stmt = (
            select(LLMConfig)
            .where(
                LLMConfig.org_id == _uuid.UUID(org_id),
                LLMConfig.enabled.is_(True),
            )
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    def _create_provider(self, config: LLMConfig):
        """Create an LLM provider from database config."""
        if config.provider == "anthropic":
            from app.services.llm.anthropic_provider import AnthropicProvider
            return AnthropicProvider(
                api_key=config.api_key_encrypted,
                model=config.model,
            )
        if config.provider == "openai":
            from app.services.llm.openai_provider import OpenAIProvider
            return OpenAIProvider(
                api_key=config.api_key_encrypted,
                model=config.model,
                base_url=config.endpoint_url,
            )
        if config.provider == "ollama":
            from app.services.llm.ollama_provider import OllamaProvider
            return OllamaProvider(
                base_url=config.endpoint_url or "http://localhost:11434",
                model=config.model,
            )
        if config.provider == "custom":
            from app.services.llm.openai_provider import OpenAIProvider
            return OpenAIProvider(
                api_key=config.api_key_encrypted,
                model=config.model,
                base_url=config.endpoint_url,
            )
        msg = f"Unknown LLM provider: {config.provider}"
        raise ValueError(msg)

    def apply_privacy_transforms(
        self,
        code: str,
        language: str,
        *,
        strip_comments_enabled: bool = True,
        anonymize_enabled: bool = False,
    ) -> str:
        """Apply privacy transforms to code before sending to LLM."""
        result = code
        if strip_comments_enabled:
            result = _strip_comments(result, language)
        if anonymize_enabled:
            result = _anonymize_variables(result)
        return result

    async def generate_fix(
        self,
        finding: Finding,
        actor: AuthenticatedUser,
        session: AsyncSession,
        *,
        strip_comments: bool = True,
        anonymize: bool = False,
    ) -> dict:
        """Generate an LLM-assisted remediation for a finding.

        Loads config from DB, applies privacy transforms, calls provider, caches result.
        """
        # Load LLM config from DB
        config = await self._get_llm_config(actor.org_id, session)
        if config is None:
            msg = "No LLM provider is configured. Go to Admin > AI Config to set one up."
            raise ValueError(msg)

        # Build code context
        props = finding.properties or {}
        code_data = props.get("code", {})
        code_lines = code_data.get("lines", [])
        raw_snippet = "\n".join(code_lines) if code_lines else ""

        # Apply privacy transforms
        snippet = self.apply_privacy_transforms(
            raw_snippet,
            props.get("language", "unknown"),
            strip_comments_enabled=strip_comments,
            anonymize_enabled=anonymize,
        )

        context = CodeContext(
            language=props.get("language", "unknown"),
            file_path=finding.location_file,
            code_snippet=snippet,
            line_number=finding.location_line,
            library=props.get("library", "unknown"),
        )

        # Check cache
        cached = await get_cached_remediation(
            rule_id=finding.rule_id,
            file_path=finding.location_file,
            line=finding.location_line,
            code_snippet=snippet,
        )
        if cached is not None:
            return {
                "finding_id": str(finding.id),
                "original_code": cached.original_code,
                "fixed_code": cached.fixed_code,
                "explanation": cached.explanation,
                "confidence": cached.confidence,
                "provider": cached.provider,
                "cached": True,
            }

        # Build finding dict for prompt
        finding_dict = {
            "rule_id": finding.rule_id,
            "name": finding.name,
            "severity": finding.severity,
            "algorithm": props.get("algorithm"),
            "quantum_status": finding.quantum_status,
        }

        # Call LLM
        provider = self._create_provider(config)
        result = await provider.generate_remediation(finding_dict, context)

        # Cache result
        await set_cached_remediation(
            rule_id=finding.rule_id,
            file_path=finding.location_file,
            line=finding.location_line,
            code_snippet=snippet,
            result=result,
        )

        return {
            "finding_id": str(finding.id),
            "original_code": result.original_code,
            "fixed_code": result.fixed_code,
            "explanation": result.explanation,
            "confidence": result.confidence,
            "provider": result.provider,
            "cached": False,
        }


remediation_service = RemediationService()
