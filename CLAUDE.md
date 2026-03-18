# CipherRadar — Claude Code Guide

## What This Project Is

CipherRadar is a **source-code-first Cryptography Bill of Materials (CBOM) platform**. It scans codebases to find every cryptographic asset (algorithms, protocols, certificates, key material), maps findings to compliance frameworks, and tracks post-quantum readiness. Output is CycloneDX 1.7 CBOM.

Full design documentation is in `docs/`. Start with `README.md` and `docs/DECISION-LOG.md`.

---

## Repository Structure

```
cli/          Go binary — cbom scan, diff, report (ADR-005)
backend/      Python/FastAPI + Celery workers
frontend/     React 19 + TypeScript dashboard
scanner/      Shared detection assets used by CLI and backend
  rules/        Semgrep YAML rules (per language)
  library-models/  Crypto API → CBOM asset type mappings
  grammars/     tree-sitter grammar configs
deploy/       Docker Compose, Kubernetes (Helm)
docs/         Design documentation and ADRs
logo/         Brand assets
```

## Key Architecture Decisions

All ADRs are in `docs/decisions/`. Decisions that affect day-to-day coding:

- **ADR-001** — Output is CycloneDX 1.7. Never invent a custom schema.
- **ADR-002** — tree-sitter is the parsing backbone for all languages.
- **ADR-003** — No build required. Scanner must work on source-only codebases.
- **ADR-004** — Detection is 3-pass: tree-sitter (Pass 1) → Semgrep (Pass 2) → Joern (Pass 3). No custom taint engine.
- **ADR-005** — CLI in Go, backend in Python/FastAPI.
- **ADR-008** — Monorepo. `scanner/` is shared between CLI and backend.

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

- **Go:** standard `gofmt` formatting; package names lowercase; no CGo except for tree-sitter bindings; use Koanf (not Viper) for config
- **Python:** `ruff` for linting and formatting; type hints required on all public functions; `pyproject.toml` for dependencies; use Taskiq (not Celery) for async tasks
- **TypeScript:** strict mode; functional components only in React; TanStack Query for server state
- **Semgrep rules:** one file per language in `scanner/rules/`; rule IDs prefixed `cbom-<lang>-<pattern>`
- **CycloneDX output:** always use the official `cyclonedx-go` / `cyclonedx-python-library` — never hand-craft the schema

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
