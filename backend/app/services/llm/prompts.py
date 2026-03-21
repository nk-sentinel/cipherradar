"""Prompt templates for LLM-assisted cryptographic remediation."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.services.llm.base import CodeContext

REMEDIATION_PROMPT = """
You are a cryptography security expert. A security scanner found the following issue:

Finding: {finding_name}
Severity: {severity}
Rule: {rule_id}
Language: {language}
Library: {library}

Code (file: {file_path}, line {line_number}):
```{language}
{code_snippet}
```

Generate a secure replacement that:
1. Fixes the cryptographic vulnerability
2. Uses the idiomatic approach for {library} in {language}
3. Maintains the same functionality
4. Is production-ready (not a stub)

Respond in JSON:
{{"original_code": "...", "fixed_code": "...", "explanation": "..."}}
"""


def build_remediation_prompt(finding: dict, context: "CodeContext") -> str:
    """Build a remediation prompt from finding metadata and code context.

    Args:
        finding: Finding metadata dict (rule_id, name, severity, etc.).
        context: Source code context from :class:`CodeContext`.

    Returns:
        Formatted prompt string ready to send to an LLM.
    """
    return REMEDIATION_PROMPT.format(
        finding_name=finding.get("name", "Unknown"),
        severity=finding.get("severity", "unknown"),
        rule_id=finding.get("rule_id", "unknown"),
        language=context.language,
        library=context.library,
        file_path=context.file_path,
        line_number=context.line_number,
        code_snippet=context.code_snippet,
    )
