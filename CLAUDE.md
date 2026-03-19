# CipherRadar — Claude Code Guide

## What This Project Is

CipherRadar is a **source-code-first Cryptography Bill of Materials (CBOM) platform**. It scans codebases to find every cryptographic asset (algorithms, protocols, certificates, key material), maps findings to compliance frameworks, and tracks post-quantum readiness. Output is CycloneDX 1.7 CBOM.

Full design documentation is in `docs/`. Start with `README.md` and `docs/DECISION-LOG.md`.

---

## Repository Structure

```
cli/          Go binary — cbom scan, diff, report (ADR-005)
backend/      Python/FastAPI + Taskiq workers
frontend/     React 19 + TypeScript dashboard
scanner/      Shared detection assets used by CLI and backend
  rules/        OpenGrep YAML rules (per language)
  library-models/  Crypto API → CBOM asset type mappings (placeholder — Phase 2)
  grammars/     tree-sitter grammar configs (placeholder — Phase 2)
deploy/       Docker Compose, Kubernetes (Helm)
docs/         Design documentation and ADRs
logo/         Brand assets
```

## Module Path

`github.com/nk-sentinel/cipherradar/cli`

## CLI Distribution

Two GoReleaser artifacts per release:
- `cbom` — lightweight binary (~15 MB), no tools bundled
- `cbom-full` — includes OpenGrep + Joern pre-bundled (~80–100 MB), for air-gapped environments

`cbom install-tools` downloads OpenGrep + Joern to `~/.cbom/tools/` for lightweight binary users.

## Shared Assets

- **OpenGrep rules** live in `scanner/rules/` as the source of truth, copied to `cli/internal/rules/data/` and embedded via `//go:embed`. Run `go generate ./internal/rules` to sync.
- **Quantum algorithm table** lives in `cli/internal/scanner/quantum/quantum.go`.
- **CycloneDX 1.7 schema** embedded in `cli/internal/validation/schema/` via `//go:embed`.

Do not load shared assets from the filesystem at runtime.

## Implementation

Phase 1 complete (`docs/11-phase1-implementation-plan.md`). Phase 2 in progress (`docs/12-phase2-implementation-plan.md`).

**Skills available** (`~/.claude/commands/`) — 37 total:

*Go CLI (Workstream A):*
- `/lint` — golangci-lint + go vet
- `/test-coverage` — test with coverage enforcement (thresholds per package)
- `/sec-review` — gosec + govulncheck
- `/dep-audit` — govulncheck (Go) / pip-audit (Python)
- `/fuzz` — fuzz scanner inputs
- `/commit` — gates lint + sec-review + dep-audit before committing
- `/benchmark` — validate performance targets (7-language corpus)
- `/profile` — CPU + memory pprof when benchmarks miss
- `/build-cross` — build + verify all platforms
- `/new-scanner` — scaffold a new language scanner
- `/new-opengrep-rule` — scaffold an OpenGrep taint rule
- `/new-joern-query` — scaffold a Joern CPG query script

*Python Backend (Workstream B):*
- `/lint-py` — ruff + mypy --strict
- `/test-py` — pytest with coverage thresholds
- `/sec-py` — bandit + pip-audit
- `/commit-py` — gates lint-py + db-validate + sec-py + dep-audit
- `/new-api-route` — scaffold FastAPI route with Pydantic models
- `/db-migrate` — Alembic migration with reversibility check
- `/db-validate` — schema integrity, CBOMStore/GAL rule enforcement
- `/db-seed` — populate database with test data
- `/load-test` — HTTP endpoint load testing (p50/p95/p99)
- `/profile-py` — py-spy flamegraph profiling
- `/webhook-test` — simulated GitHub/GitLab/Bitbucket webhooks

*React Frontend (Workstream C):*
- `/lint-fe` — eslint + tsc --noEmit
- `/test-fe` — vitest with coverage thresholds
- `/sec-fe` — npm audit
- `/commit-fe` — gates lint-fe + sec-fe
- `/build-fe` — production build + bundle size validation
- `/new-page-fe` — scaffold page with TanStack Query/Router + RBAC guard
- `/mock-api-fe` — MSW mock API layer validation
- `/a11y-fe` — WCAG 2.1 AA accessibility checks (axe-core)

*Cross-workstream:*
- `/adr` — create ADR + update decision log
- `/openapi-sync` — OpenAPI spec validation + TypeScript codegen
- `/docker-compose` — dev stack management + health checks
- `/docker-build` — Docker image build + security validation
- `/e2e-test` — full-stack Playwright integration tests
- `/changelog` — generate changelog from git history

**Hooks:** `go vet` (.go), `ruff check` (.py), `tsc --noEmit` (.ts/.tsx) — all run automatically after file writes.

## Key Architecture Decisions

All ADRs are in `docs/decisions/`. Decisions that affect day-to-day coding:

- **ADR-001** — Output is CycloneDX 1.7. Never invent a custom schema.
- **ADR-002** — tree-sitter is the parsing backbone for all languages.
- **ADR-003** — No build required. Scanner must work on source-only codebases.
- **ADR-004** — Detection is 3-pass: tree-sitter (Pass 1) → OpenGrep (Pass 2) → Joern (Pass 3). No custom taint engine.
- **ADR-005** — CLI in Go, backend in Python/FastAPI.
- **ADR-008** — Monorepo. `scanner/` is shared between CLI and backend.
- **ADR-011** — Joern Pass 3 via subprocess (same pattern as OpenGrep).
- **ADR-012** — DB schema: CBOMStore abstraction, TimescaleDB hypertables, JSONB+GIN, GAL.
- **ADR-013** — Auth: JWT + scoped API keys. 7 RBAC roles: Org Admin, Security Manager, Security Engineer, **Team Manager**, Compliance Auditor, Developer, Guest/Viewer (`docs/09-rbac.md` v2).
- **ADR-014** — Git provider abstraction: common interface for GitHub/GitLab/Bitbucket.
- **ADR-015** — Frontend: React 19, TanStack Query/Router, shadcn/ui, 3 CSS themes, MSW mock API. UI mockup: `frontend/mockups/full-mockup-v2.html`.

---

## Commands

### CLI (Go)
```bash
cd cli
go build ./...          # build
go test ./...           # test
go vet ./...            # vet
```

### Backend (Python)
```bash
cd backend
python -m pytest        # test
ruff check .            # lint
ruff format .           # format
```

### Frontend (Node)
```bash
cd frontend
npm install
npm run dev             # dev server
npm run build           # production build
npm test                # test
```

### Full stack (Docker Compose)
```bash
docker compose -f deploy/docker-compose.yml up
```

---

## Conventions

- **Go:** standard `gofmt` formatting; package names lowercase; no CGo except for tree-sitter bindings; use `gopkg.in/yaml.v3` for YAML config; Koanf deferred to Phase 2 if needed
- **Python:** `ruff` for linting and formatting; type hints required on all public functions; `pyproject.toml` for dependencies; use Taskiq (not Celery) for async tasks
- **TypeScript:** strict mode; functional components only in React; TanStack Query for server state
- **OpenGrep rules:** one file per language in `scanner/rules/`; rule IDs prefixed `cbom-<lang>-<pattern>`
- **CycloneDX output:** internal structs in `cli/internal/cyclonedx17/` for cryptoProperties + `cli/internal/output/converter.go` for BOM envelope. `cyclonedx-go` was not adopted (only supports 1.6). Backend uses `cyclonedx-python-lib` v11.7.0 which supports 1.7 natively. Never hand-craft the schema.

## Commits

- No co-author tags in commit messages
- Commit messages: imperative mood, concise, lowercase after the first word
- Stage specific files — never `git add .` blindly

## Things to Never Do

- Never require a build step to run the scanner (ADR-003)
- Never store CBOM JSON as a Postgres column in production (use CBOMStore abstraction)
- Never bypass the Graph Abstraction Layer (GAL) with raw CTE queries outside `GraphRepository`
- Never add `policy:write` scope to API keys (UI-only per resolved OQ-RBAC-7)
- Never commit `.env` files or secrets
