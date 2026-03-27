# Plan 5 Pattern Reference: Admin & Config Implementation Patterns

Extends plan2-patterns.md. Read that first.

## Integration Token Pattern (D3)

Tokens encrypted at rest. Store hash for lookup, encrypted blob for API calls.
```python
import secrets, hashlib
raw_token = "ghp_abc123..."  # user provides PAT
token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
token_prefix = raw_token[:8] + "..."
# Store: token_hash (for lookup), encrypted token (for API calls)
# Phase 4.5: store raw token (encryption deferred to production hardening)
```

## LLM Provider Abstraction (D5)

```python
class LLMProvider:
    async def generate_fix(self, finding_context: dict) -> LLMResponse: ...

class AnthropicProvider(LLMProvider): ...
class OpenAIProvider(LLMProvider): ...
class OllamaProvider(LLMProvider): ...
class CustomProvider(LLMProvider): ...  # OpenAI-compatible endpoint

def get_provider(config: LLMConfig) -> LLMProvider:
    providers = {"anthropic": AnthropicProvider, "openai": OpenAIProvider, ...}
    return providers[config.provider](config)
```

## Policy Cascade (D26) — Same as D18/D20

```python
async def resolve_policy(project_id, session):
    # project overrides → group overrides → org defaults
    # Locked rules cannot be overridden at lower levels
```

## Custom Rule Validation (D27)

```python
import yaml

def validate_opengrep_rule(content: str) -> list[str]:
    """Validate YAML is a valid OpenGrep rule. Return list of errors."""
    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return [f"Invalid YAML: {e}"]
    errors = []
    if "rules" not in rule:
        errors.append("Missing 'rules' key")
    for r in rule.get("rules", []):
        if "id" not in r: errors.append("Rule missing 'id'")
        if "pattern" not in r and "patterns" not in r: errors.append("Rule missing pattern")
    return errors
```

## Audit Log Query Pattern (D28)

```python
async def query_audit_log(filters: AuditLogFilters, page, per_page, session):
    stmt = select(AuditLog).where(AuditLog.org_id == filters.org_id)
    if filters.date_from:
        stmt = stmt.where(AuditLog.created_at >= filters.date_from)
    if filters.date_to:
        stmt = stmt.where(AuditLog.created_at <= filters.date_to)
    if filters.user_id:
        stmt = stmt.where(AuditLog.user_id == filters.user_id)
    if filters.action_type:
        stmt = stmt.where(AuditLog.action_type == filters.action_type)
    return await paginate(stmt.order_by(AuditLog.created_at.desc()), page, per_page, session)
```
