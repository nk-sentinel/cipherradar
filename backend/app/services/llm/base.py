"""Abstract base class for LLM providers (ADR-027)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class CodeContext:
    """Source code context surrounding a cryptographic finding."""

    language: str  # "python", "java", etc.
    file_path: str
    code_snippet: str  # the code around the finding
    line_number: int
    library: str  # "hashlib", "javax.crypto", etc.


@dataclass
class RemediationResult:
    """Result of an LLM-generated remediation suggestion."""

    original_code: str
    fixed_code: str
    explanation: str  # why this fix works
    language: str
    confidence: float  # 0.0-1.0
    provider: str  # "anthropic", "openai", "ollama"


class LLMProvider(ABC):
    """Abstract interface for LLM-based remediation providers.

    Concrete implementations wrap a specific LLM API (Anthropic, OpenAI, Ollama)
    and translate findings + code context into remediation suggestions.
    """

    @abstractmethod
    async def generate_remediation(
        self, finding: dict, context: CodeContext
    ) -> RemediationResult:
        """Generate a code remediation for the given cryptographic finding.

        Args:
            finding: Finding metadata dict with keys like rule_id, name, severity.
            context: Source code context surrounding the finding.

        Returns:
            A RemediationResult with the original code, fixed code, and explanation.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check whether the LLM provider is reachable and operational.

        Returns:
            True if the provider is healthy, False otherwise.
        """
        ...
