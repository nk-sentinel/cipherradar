# Phase 2 — Implementation Plan

> **Document version:** v1
> **Last updated:** 2026-03-19
> **Status:** Draft

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-19 | Initial plan — orchestrator + subagent model, 3 workstreams, 15 milestones |

---

## Overview

Phase 2 extends CipherRadar from a 3-language CLI tool to a full-stack platform: 7 language scanners, a FastAPI backend with compliance engine, and a React dashboard. It is implemented using the same **orchestrator + subagent model** as Phase 1.

**Key structural change from Phase 1:** Phase 2 has **three fully independent workstreams** that run in parallel. Each workstream has its own orchestrator and milestone gates. Cross-workstream integration happens at defined milestones only (Workstream C consumes Workstream B APIs at C-M3).

```
Workstream A — CLI: More Languages + Detection      (Go)
Workstream B — Backend: API + Data                   (Python/FastAPI)
Workstream C — Frontend: Dashboard                   (React 19 + TypeScript)

   A ────────────────────────────────────────────────►
   B ────────────────────────────────────────────────►
   C ──────────────────────┬─────────────────────────►
                           │
                    C depends on B-M3
                    (API contracts ready)
```

- **Orchestrator** — strictly coordinates. Assigns subagents in dependency order, merges integration points (scanner registry, API contracts, frontend routes), and runs all quality/security validation skills after each subagent completes. Never writes implementation code.
- **Subagents** — each owns a single concern. Runs its own skills during implementation. Reports back to the orchestrator when done.

All commits are gated through the `/commit` skill. No code is merged without passing the orchestrator's milestone-close gate.

---

## Model Configuration

All agents use the same model and effort level — no mixing.

| Setting | Value |
|---|---|
| **Model** | Opus 4.6 (1M context) |
| **Effort** | High |
| **Applies to** | All 3 workstream orchestrators + all subagents |

---

## Skills Reference

### Existing Skills (Phase 1 — used by Workstream A)

| Skill | Category | Purpose |
|---|---|---|
| `/adr` | Architecture | Create a new ADR + update decision log |
| `/lint` | Quality | `go vet` + `golangci-lint` (Go); `ruff` (Python) |
| `/test-coverage` | Quality | Run tests with coverage; enforce per-package thresholds |
| `/sec-review` | Security | `gosec` + `govulncheck` (Go); `bandit` (Python) |
| `/dep-audit` | Security | `govulncheck` (Go); `pip-audit` (Python) |
| `/fuzz` | Security | Go fuzz tests on scanner inputs |
| `/commit` | Workflow | Gates lint + sec-review + dep-audit before every commit |
| `/benchmark` | Performance | Validate scan throughput |
| `/profile` | Performance | CPU + memory pprof when benchmarks miss |
| `/build-cross` | Cross-platform | Build for macOS/Linux/Windows; verify each binary |
| `/new-scanner` | Scaffolding | Scaffold new language scanner |
| `/new-opengrep-rule` | Scaffolding | Scaffold OpenGrep YAML taint rule |

### New Skills (Phase 2)

| Skill | Category | Workstream | Purpose |
|---|---|---|---|
| `/lint-py` | Quality | B | `ruff check .` + `ruff format --check .` + `mypy --strict` from `backend/` |
| `/test-py` | Quality | B | `pytest` with coverage enforcement; min 80% API routes, 85% compliance, 70% workers |
| `/sec-py` | Security | B | `bandit -r . --severity-level medium` + `pip-audit` from `backend/` |
| `/commit-py` | Workflow | B | Gates `/lint-py` + `/sec-py` + `/dep-audit` before every commit |
| `/lint-fe` | Quality | C | `eslint .` + `tsc --noEmit` from `frontend/` |
| `/test-fe` | Quality | C | `vitest run --coverage`; min 70% components, 80% hooks/utilities |
| `/sec-fe` | Security | C | `npm audit --audit-level=moderate` from `frontend/` |
| `/commit-fe` | Workflow | C | Gates `/lint-fe` + `/sec-fe` before every commit |
| `/new-api-route` | Scaffolding | B | Scaffold FastAPI router with Pydantic models, dependency injection, tests |
| `/db-migrate` | Database | B | Create + run Alembic migration; validate up/down; check for data loss |
| `/openapi-sync` | Contract | B+C | Validate OpenAPI spec matches implementation; generate TypeScript client types |

**Hooks:**
- `go vet` runs after every `.go` file write/edit (existing)
- `ruff check` runs after every `.py` file write/edit (new)
- `tsc --noEmit` runs after every `.ts`/`.tsx` file write/edit (new)

---

## Workstream A — CLI: More Languages + Detection (Go)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **A-M1** | Agent-GoScanner | — | No | Go scanner: `crypto/*` stdlib (aes, cipher, des, dsa, ecdh, ecdsa, ed25519, hmac, md5, rand, rc4, rsa, sha1, sha256, sha512, tls, x509), `golang.org/x/crypto` (chacha20poly1305, nacl, argon2, bcrypt, scrypt, ssh, hkdf). tree-sitter-go grammar, constprop, quantum tagging. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-KotlinScanner | — | Yes | Kotlin scanner: reuse Java library models (JCA/JCE, Bouncy Castle), Kotlin-specific extensions. tree-sitter-kotlin grammar, constprop. Extensions `.kt`, `.kts`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | **Orchestrator gate** | All A-M1 | — | Merge scanner registry (add Go + Kotlin), validate full CLI build | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **A-M2** | Agent-CSharpScanner | A-M1 | No | C# scanner: `System.Security.Cryptography` (Aes, RSA, ECDsa, SHA256, HMAC, Rfc2898DeriveBytes), BouncyCastle.NET. tree-sitter-c-sharp grammar, constprop. Extensions `.cs`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M2** | Agent-PHPScanner | A-M1 | Yes | PHP scanner: `openssl_encrypt/decrypt/sign/pkey_new`, `hash/hash_hmac/hash_pbkdf2`, `password_hash/verify`, `sodium_crypto_*`. tree-sitter-php grammar, constprop. Extensions `.php`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M2** | Agent-OpenGrepRules-New | A-M1 | Yes | OpenGrep rules for Go, Kotlin, C#, PHP. Min 3 rules/language: hardcoded key, static IV, weak PRNG. | `/new-opengrep-rule`, `/lint` |
| **A-M2** | **Orchestrator gate** | All A-M2 | — | Merge registry (7 languages), merge rules, validate build | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **A-M3** | Agent-DetectionExpansion | A-M2 | No | Certificate parsing from PEM, certificate expiry checking, PBKDF2/bcrypt/scrypt/Argon2 iteration checks (all 7 langs), ECB mode detection, PKCS1v15 flagging, JWT/JOSE alg detection | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M3** | Agent-JoernIntegration | A-M2 | Yes | Joern Pass 3: `cli/internal/joern/` (runner, parser, dedup). Binary discovery (same pattern as OpenGrep). CPG export to JSON, finding extraction, merge with Pass 1+2. `--deep` flag. Graceful skip if not installed. | `/lint`, `/sec-review`, `/test-coverage` |
| **A-M3** | Agent-JoernRules | Agent-JoernIntegration | No | Joern query scripts: inter-procedural crypto patterns (key flow across methods, factory patterns). Min: Java + Python + JS. Stored in `scanner/joern-queries/`. | `/lint`, `/test-coverage` |
| **A-M3** | **Orchestrator gate** | All A-M3 | — | Full Workstream A close: 7 languages, Pass 1+2+3, detection expansion | `/lint`, `/sec-review`, `/dep-audit`, `/test-coverage`, `/fuzz`, `/benchmark`, `/build-cross` |

---

## Workstream B — Backend: API + Data (Python/FastAPI)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **B-M1** | Agent-BackendSkeleton | — | No | FastAPI app: `backend/app/` with main.py, config (Pydantic Settings), db (SQLAlchemy 2.0 async + Alembic), models, schemas, router stubs. PostgreSQL 17 + TimescaleDB. Redis. Taskiq. Docker Compose dev services. Health endpoint. | `/lint-py`, `/sec-py`, `/test-py` |
| **B-M1** | Agent-DBSchema | Agent-BackendSkeleton | No | Alembic initial migration: organisations, projects, scans, cbom_documents, findings, policy_sets, compliance_mappings. TimescaleDB hypertables for scan_metrics. CBOMStore abstraction. GIN indexes. | `/db-migrate`, `/lint-py`, `/test-py` |
| **B-M1** | **Orchestrator gate** | All B-M1 | — | FastAPI starts, migrations apply, health returns 200, Taskiq connects | `/lint-py`, `/sec-py`, `/test-py` |
| **B-M2** | Agent-ScanAPI | B-M1 | No | `POST /api/v1/scans`, `GET /api/v1/scans/{id}`, `GET /api/v1/scans/{id}/cbom`. Taskiq worker shells out to `cbom` CLI. Status: queued → running → completed/failed. CBOM stored via CBOMStore. Pagination. | `/new-api-route`, `/lint-py`, `/sec-py`, `/test-py` |
| **B-M2** | Agent-AuthJWT | B-M1 | Yes | JWT login/refresh, API keys for CI/CD. Scopes: `scan:read`, `scan:write`, `cbom:read`, `project:read`, `project:write`. No `policy:write` on API keys. | `/lint-py`, `/sec-py`, `/test-py` |
| **B-M2** | **Orchestrator gate** | All B-M2 | — | Scan submission → poll → retrieve works e2e; JWT protects routes; API keys work | `/lint-py`, `/sec-py`, `/test-py` |
| **B-M3** | Agent-GitIntegrations | B-M2 | No | GitHub (OAuth, webhooks, Checks API, PR comments). GitLab (OAuth, webhooks, MR notes). Bitbucket Cloud + Data Center. Common `GitProvider` interface. Webhook signature verification. | `/new-api-route`, `/lint-py`, `/sec-py`, `/test-py` |
| **B-M3** | Agent-ComplianceEngine | B-M2 | Yes | NIST SP 800-131A (Acceptable/Deprecated/Disallowed). FIPS 140-3 checks. Quantum Risk Score (0-100). Migration Priority Queue. Mappings in `scanner/library-models/` embedded via `importlib.resources`. | `/lint-py`, `/test-py` |
| **B-M3** | Agent-CBOMManagement | B-M2 | Yes | CBOM versioning (immutable snapshots). Diff API (`GET /api/v1/cbom/diff`). Merge API (`POST /api/v1/cbom/merge`). | `/new-api-route`, `/lint-py`, `/test-py` |
| **B-M3** | **Orchestrator gate** | All B-M3 | — | GitHub webhook → scan → check run; compliance scores correct; OpenAPI spec frozen for frontend | `/lint-py`, `/sec-py`, `/test-py`, `/openapi-sync` |
| **B-M4** | Agent-BackendReports | B-M3 | No | PDF (ReportLab): quantum readiness, compliance gap. HTML (Jinja2). Excel/CSV (openpyxl). Taskiq background task. `GET /api/v1/reports/{scan_id}?format=pdf|html|csv`. | `/lint-py`, `/test-py` |
| **B-M4** | Agent-BackendPerformance | B-M3 | Yes | CBOM retrieval < 200ms (GIN indexes, Redis caching). Connection pooling (asyncpg). Scan queue concurrency limits. Load test. | `/lint-py`, `/test-py` |
| **B-M4** | **Orchestrator gate** | All B-M4 | — | Full Workstream B close: all API routes, git integrations, compliance, reports, perf targets | `/lint-py`, `/sec-py`, `/test-py`, `/openapi-sync` |

---

## Workstream C — Frontend: Dashboard (React 19 + TypeScript)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **C-M1** | Agent-FrontendSkeleton | — | No | Vite + React 19 + TS strict. shadcn/ui + Tailwind. TanStack Query + Router. Layout shell. Auth context (JWT). API client from OpenAPI spec. | `/lint-fe`, `/test-fe` |
| **C-M1** | **Orchestrator gate** | All C-M1 | — | `npm run build` succeeds, tests pass, dev server starts, auth flow works with mock API | `/lint-fe`, `/test-fe`, `/sec-fe` |
| **C-M2** | Agent-RepositoryViews | C-M1 | No | Repo list (table: name, last scan, findings, risk score, compliance badges). Repo detail (scan history, CBOM summary). Project settings. | `/lint-fe`, `/test-fe` |
| **C-M2** | Agent-ScanViews | C-M1 | Yes | Scan summary (severity bar chart, algo distribution pie, quantum breakdown). Scan trigger button. Scan comparison (diff view). | `/lint-fe`, `/test-fe` |
| **C-M2** | Agent-FindingViews | C-M1 | Yes | Finding list (filterable table: severity, confidence, language, algo, quantum, compliance). Finding detail (snippet, location, remediation). Bulk actions. | `/lint-fe`, `/test-fe` |
| **C-M2** | **Orchestrator gate** | All C-M2 | — | All pages render, filters work, data flows from mock API | `/lint-fe`, `/test-fe`, `/sec-fe` |
| **C-M3** | Agent-QuantumReadinessView | C-M2 | No | Risk score gauge (0-100), algo breakdown by quantum status, PQC migration priority list, trend chart. | `/lint-fe`, `/test-fe` |
| **C-M3** | Agent-ComplianceView | C-M2 | Yes | Per-framework compliance score, gap list, PDF download button. | `/lint-fe`, `/test-fe` |
| **C-M3** | Agent-FrontendAPIIntegration | C-M2 + **B-M3** | No | Replace mock API with live backend. Regenerate TS types from frozen OpenAPI spec. CORS config. | `/lint-fe`, `/test-fe`, `/openapi-sync` |
| **C-M3** | **Orchestrator gate** | All C-M3 | — | Full Workstream C close: all pages against live backend, production build clean | `/lint-fe`, `/test-fe`, `/sec-fe`, `/openapi-sync` |

---

## Cross-Workstream Dependencies

```
A-M1 ─────► A-M2 ─────► A-M3           (sequential within A)
B-M1 ─────► B-M2 ─────► B-M3 ─────► B-M4   (sequential within B)
C-M1 ─────► C-M2 ─────► C-M3           (sequential within C)
                          │
                          └── C-M3 depends on B-M3
                              (OpenAPI spec frozen, API routes available)
```

| Dependency | From | To | What |
|---|---|---|---|
| API contract | B-M3 | C-M3 | Frontend integrates with live backend. B-M3 gate freezes OpenAPI spec. |
| CLI binary | Phase 1 | B-M2 | Backend scan worker shells out to `cbom` CLI. Upgraded to 7-lang binary when A-M3 completes. |
| Shared assets | `scanner/library-models/` | A + B | CLI embeds via `//go:embed`, backend via `importlib.resources`. Compliance engine (B-M3) populates NIST/FIPS mappings. |

---

## New ADRs Required

| ADR | Title | Workstream | Timing |
|---|---|---|---|
| ADR-011 | Joern Integration Model — subprocess vs persistent server vs container | A | Before A-M3 |
| ADR-012 | Backend Database Schema — CBOMStore, TimescaleDB hypertables | B | Before B-M1 |
| ADR-013 | Authentication Model — JWT + API keys, scope design | B | Before B-M2 |
| ADR-014 | Git Provider Abstraction — common interface for GitHub/GitLab/Bitbucket | B | Before B-M3 |
| ADR-015 | Frontend Architecture — routing, state management, API client generation | C | Before C-M1 |

---

## Orchestrator Rules

### Global (all workstreams)

1. **Never write implementation code.** Assign, coordinate, merge, validate only.
2. **Never hand off broken code.** Run lint + sec-review after every subagent.
3. **Parallel agents get the same base.** Clean build before launching parallel agents.
4. **Milestone-close gates are non-negotiable.** No exceptions.
5. **Escalate blockers immediately.** Surface to user before proceeding.

### Workstream A

6. Scanner registry merges are the orchestrator's responsibility.
7. New scanners follow Phase 1 patterns exactly (same interface, constprop, fuzz template).
8. Joern Pass 3 is optional — graceful skip if not installed.

### Workstream B

9. OpenAPI spec is the contract — frozen at B-M3 before C-M3 begins.
10. Never store CBOM JSON as a Postgres column (use CBOMStore abstraction).
11. Never bypass the Graph Abstraction Layer.
12. Shared assets embedded via `importlib.resources`, never loaded from filesystem at runtime.

### Workstream C

13. Strict TypeScript — `strict: true`, no `any` except generated code.
14. Functional components only — no class components.
15. TanStack Query for all server state — no `useState` + `useEffect` fetch patterns.
16. Mock API for C-M1 and C-M2 — real API integration only at C-M3.

---

## Phase 2 Success Criteria

| Criterion | Gate | Workstream |
|---|---|---|
| 7 languages supported | A-M2 gate | A |
| Joern Pass 3 functional for Java, Python, JS | A-M3 gate | A |
| Certificate parsing + expiry detection | A-M3 gate | A |
| KDF iteration count checking (all 7 langs) | A-M3 gate | A |
| Compliance gap reports pass GRC review | B-M4 gate | B |
| API response < 200ms for CBOM retrieval | B-M4 gate | B |
| Quantum Risk Score computes correctly | B-M3 gate | B |
| GitHub Checks API posts finding annotations | B-M3 gate | B |
| Dashboard renders repos, scans, findings | C-M2 gate | C |
| Quantum + compliance views functional | C-M3 gate | C |
| Full stack via Docker Compose | Final integration | B + C |
| No HIGH/CRITICAL security findings | Every gate | All |
| FP rate < 10% for High/Critical (new langs) | A-M2 gate | A |
| All platforms build (CLI) | Every A gate | A |

---

## Milestone Sequencing

```
Week 1-2:   A-M1 + B-M1 + C-M1    (all start in parallel)
Week 3-4:   A-M2 + B-M2 + C-M2    (all advance in parallel)
Week 5-7:   A-M3 + B-M3 + C-M2    (C-M2 may still be in progress)
Week 8-9:          B-M4 + C-M3    (C-M3 waits for B-M3 API freeze)
Week 10:    Final integration      (Docker Compose full stack)
```

Estimated duration: 10-12 weeks (Months 4-6 per roadmap).
