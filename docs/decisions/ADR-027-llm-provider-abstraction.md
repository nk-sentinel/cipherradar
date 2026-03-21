# ADR-027: LLM Provider Abstraction — Multi-Provider with Anthropic Default

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

CipherRadar Phase 4 adds AI-assisted code remediation: when a finding identifies a vulnerable or non-quantum-safe cryptographic usage, the system can suggest a concrete code fix. This requires integration with a large language model (LLM) API. Enterprise customers have diverse requirements — some mandate specific providers, others operate in air-gapped environments where only self-hosted models are acceptable.

The LLM integration lives in the backend (Python/FastAPI), not the CLI. The CLI remains a stateless scanning tool; remediation suggestions are generated server-side and surfaced via the API, IDE extensions (ADR-029, ADR-030), and the frontend dashboard.

---

## Decision

### Abstract provider interface

A Python abstract base class `LLMProvider` defines the contract for all LLM integrations:

```python
class LLMProvider(ABC):
    @abstractmethod
    async def generate_remediation(
        self,
        finding: Finding,
        code_context: CodeContext,
    ) -> RemediationSuggestion: ...
```

### Three concrete implementations

| Provider | Class | Use Case | Model |
|---|---|---|---|
| Anthropic (default) | `AnthropicProvider` | Cloud-connected deployments | Claude for code remediation |
| OpenAI | `OpenAIProvider` | Enterprise customers with OpenAI contracts | GPT-4 alternative |
| Ollama | `OllamaProvider` | Air-gapped enterprise; self-hosted models | Local models (CodeLlama, Mistral, etc.) |

### Configuration

Provider selection via environment variable:

```
CRADAR_LLM_PROVIDER=anthropic|openai|ollama
CRADAR_LLM_API_KEY=<key>           # Not needed for Ollama
CRADAR_LLM_MODEL=<model-override>  # Optional; each provider has a sensible default
CRADAR_LLM_BASE_URL=<url>          # Required for Ollama; optional for others (proxy support)
```

### Caching

Remediation suggestions are cached by finding fingerprint (algorithm + language + code pattern hash). The same finding in a different file produces the same remediation — no redundant API calls. Cache stored in the backend database with configurable TTL (default: 30 days).

### Privacy and consent

Code snippets are sent to the LLM provider only when the organisation has an explicit opt-in consent flag enabled (`CRADAR_LLM_CODE_CONSENT=true`). Without consent, remediation uses only the finding metadata (algorithm name, quantum status, framework) without source code — producing generic guidance instead of line-level fixes.

### Scope

This integration lives entirely in the backend Python service. The CLI does not call LLM APIs directly. IDE extensions and the frontend consume remediation suggestions via the backend REST API.

---

## Options Considered

### Option A: Anthropic-only (rejected)
Simplest implementation but locks out enterprise customers with existing OpenAI contracts or air-gapped requirements. The abstraction cost is minimal (one interface, three thin implementations).

### Option B: LangChain abstraction (rejected)
LangChain provides a provider abstraction but adds a heavy dependency (~50+ transitive packages) for a feature that requires only a single API call pattern. The three providers each have well-documented Python SDKs. Direct integration is simpler and more maintainable.

### Option C: CLI-side LLM integration (rejected)
Running LLM calls from the CLI would require API keys on every developer machine and network access from scan environments. Centralising in the backend allows org-level key management, caching, consent enforcement, and audit logging.

---

## Consequences

- **Positive:** Enterprise customers can use their preferred or mandated LLM provider
- **Positive:** Air-gapped environments supported via Ollama with local models
- **Positive:** Finding-level caching eliminates redundant API calls across scans
- **Positive:** Opt-in consent model respects code confidentiality by default
- **Negative:** Three provider implementations to maintain and test
- **Negative:** Remediation quality varies across providers — Anthropic/OpenAI will outperform smaller local models
- **Negative:** Backend gains a new external dependency (LLM API availability)

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/07-tech-stack.md` | LLM provider abstraction added; `anthropic`, `openai`, `ollama` Python SDKs listed |
| `docs/02-architecture.md` | Backend service diagram: LLM provider component added |
| `docs/09-rbac.md` | New permission: `remediation:read` for accessing LLM-generated suggestions |
| `backend/` | New `backend/app/llm/` package with provider interface and implementations |
