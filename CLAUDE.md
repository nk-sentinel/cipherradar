# CipherRadar — Claude Code Guide

## What This Project Is

CipherRadar is a **source-code-first Cryptography Bill of Materials (CBOM) platform**. It scans codebases to find every cryptographic asset (algorithms, protocols, certificates, key material), maps findings to compliance frameworks, and tracks post-quantum readiness. Output is CycloneDX 1.7 CBOM.

Full design documentation is in `docs/`. Start with `README.md` and `docs/DECISION-LOG.md`.

---

## Repository Structure

```
cli/          Go binary — cradar scan, diff, report (ADR-005, ADR-024)
backend/      Python/FastAPI + Taskiq workers
frontend/     React 19 + TypeScript dashboard
scanner/      Shared detection assets used by CLI and backend
  rules/        OpenGrep YAML rules (per language)
  library-models/  Crypto API → CBOM asset type mappings + compliance framework YAMLs
  grammars/     tree-sitter grammar configs
deploy/       Docker Compose, Kubernetes (Helm)
docs/         Design documentation and ADRs
logo/         Brand assets
```

## Module Path

`github.com/nk-sentinel/cipherradar/cli`

Note: The Go module path is unchanged by the binary rename (ADR-024). The module path is an internal identifier; the user-facing binary name is `cradar`.

## CLI Distribution

Two GoReleaser artifacts per release (renamed from `cbom`/`cbom-full` per ADR-024):
- `cradar` — lightweight binary (~15 MB), no tools bundled
- `cradar-full` — includes OpenGrep + YARA-X pre-bundled (~50 MB), for air-gapped environments

`cradar install-tools` downloads OpenGrep + YARA-X to `~/.cradar/tools/` for lightweight binary users. Joern was removed per ADR-033 — all Joern patterns are now covered by OpenGrep taint rules.

`cbom` is retained as a legacy alias (symlink) during Phase 3 for backward compatibility. The alias prints a deprecation warning and will be removed in a future release.

## Shared Assets

- **OpenGrep rules** live in `scanner/rules/` as the source of truth, copied to `cli/internal/rules/data/` and embedded via `//go:embed`. Run `go generate ./internal/rules` to sync.
- **Quantum algorithm table** lives in `cli/internal/scanner/quantum/quantum.go`.
- **CycloneDX 1.7 schema** embedded in `cli/internal/validation/schema/` via `//go:embed`.

Do not load shared assets from the filesystem at runtime.

## Implementation

Phase 1 complete (`docs/11-phase1-implementation-plan.md`). Phase 2 complete (`docs/12-phase2-implementation-plan.md`). Phase 3 complete (`docs/13-phase3-implementation-plan.md`) — all 19 milestones delivered, Docker deployment verified. Phase 4 complete (`docs/14-phase4-implementation-plan.md`) — binary scanning (Pass 3 YARA-X), pre-commit hook, OTel runtime-enrichment, agility score.

**Recent (v0.4.0-rc.4):** keystore format coverage — JCEKS + BKS parsed via pure-Go readers, BCFKS/UBER/macOS Keychain/Mozilla NSS captured presence-only, PKCS12 `.pkcs12`/`.pk12` variants, config/source keystore-password harvesting (coverage-only); richer certificate metadata (`cradar:cert:*`) + unparsed-cert surfacing (`cbom-cert-unparsed`); tooling upgraded to OpenGrep v1.25.0 + YARA-X v1.19.0. See CHANGELOG.md.

**Phase 3 deliverables:**
- 12 language scanners + container scanning + config file scanning (nginx, httpd, openssl.cnf, java.security, k8s, Dockerfiles)
- 6 compliance frameworks (NIST, FIPS, PCI-DSS, CNSA 2.0, ISO 27001, EU CRA)
- Multi-tenant RBAC with PostgreSQL RLS, 7-role enforcement, group hierarchy
- Notifications (email, Teams, WebSocket) + Jira integration
- CBOM signing (Sigstore/cosign)
- Portfolio API with Redis caching
- Dependency-Track integration
- SonarQube generic issue export
- Prometheus metrics endpoint
- Helm chart + Kustomize manifests (dev/staging/prod overlays)
- CLI renamed to `cradar` with `--push` flag
- 5 output formats (CycloneDX, SARIF, text, PDF, SonarQube Generic)
- 30 Go packages, 310+ backend tests
- 33 ADRs (ADR-001 through ADR-040, with gaps)

**Skills available** (`~/.claude/commands/`) — 36 total:

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

33 ADRs total (ADR-001 through ADR-040, with gaps) in `docs/decisions/`. Decisions that affect day-to-day coding:

- **ADR-001** — Output is CycloneDX 1.7. Never invent a custom schema.
- **ADR-002** — tree-sitter is the parsing backbone for all languages.
- **ADR-003** — No build required. Scanner must work on source-only codebases.
- **ADR-004** — Detection is 3-pass: tree-sitter AST + constant propagation (Pass 1) → OpenGrep taint rules (Pass 2) → YARA-X binary content scanning (Pass 3, opt-in per ADR-039). The original Joern Pass 3 was removed entirely per ADR-033 — its patterns are covered by OpenGrep taint rules with 19x better performance. Default is `--passes 1,2`; `--fast` = Pass 1 only; `--deep` = `1,2,3`. 207 OpenGrep rules across 12 language files (154 inventory + 53 security).
- **ADR-005** — CLI in Go, backend in Python/FastAPI.
- **ADR-008** — Monorepo. `scanner/` is shared between CLI and backend.
- **ADR-011** — ~~Joern Pass 3 via subprocess~~ — superseded by ADR-033. Joern removed; all patterns covered by OpenGrep rules.
- **ADR-012** — DB schema: CBOMStore abstraction, TimescaleDB hypertables, JSONB+GIN, GAL.
- **ADR-013** — Auth: JWT + scoped API keys. 7 RBAC roles: Org Admin, Security Manager, Security Engineer, **Team Manager**, Compliance Auditor, Developer, Guest/Viewer (`docs/09-rbac.md` v2).
- **ADR-014** — Git provider abstraction: common interface for GitHub/GitLab/Bitbucket.
- **ADR-015** — Frontend: React 19, TanStack Query/Router, shadcn/ui, 3 CSS themes, MSW mock API. UI mockup: `frontend/mockups/full-mockup-v2.html`.
- **ADR-016** — Container image scanning: OCI layer extraction via go-containerregistry.
- **ADR-017** — Multi-tenant data isolation: RLS with org_id, materialized path for group hierarchy.
- **ADR-018** — SBOM ingestion and CBOM-SBOM linking via purl matching.
- **ADR-019** — Notification architecture: transactional outbox pattern with Taskiq workers.
- **ADR-020** — CBOM signing: Sigstore keyless (Fulcio + Rekor) for SaaS, org-managed keys for air-gapped.
- **ADR-021** — SonarQube plugin: thin API client, no embedded scanner.
- **ADR-022** — Kubernetes deployment: Helm primary, raw manifests + Kustomize as alternative.
- **ADR-023** — Compliance framework extensibility: YAML-driven rules in `scanner/library-models/`.
- **ADR-024** — CLI binary rename: `cbom` → `cradar`. `cbom` kept as legacy alias during Phase 3.
- **ADR-025** — CLI-to-portal push: `cradar scan --push` uploads results to portal. `.cradar.yml` config file for defaults.

---

## Commands

### CLI (Go)
```bash
cd cli
go build -o cradar ./cmd/cradar   # build (binary renamed per ADR-024; entry point remains cmd/cradar until code rename)
go test ./...                    # test
go vet ./...                     # vet

# Scan a project
cradar scan /path/to/project --format text
cradar scan /path/to/project --format cyclonedx-json --output cbom.json --validate

# Scan and push to portal (ADR-025)
cradar scan /path/to/project --push --project "my-service" --api-key $CRADAR_API_KEY

# Policy check
cradar policy check cbom.json --policy policy.cradar.yml --fail-on high

# Diff two scans
cradar diff cbom-before.json cbom-after.json
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
