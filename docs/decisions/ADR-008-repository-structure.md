# ADR-008: Repository Structure — Monorepo

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-18 |
| **Deciders** | Architecture session |

---

## Context

CipherRadar consists of four distinct components with different languages and runtimes:

- **CLI** — Go binary (`cbom scan`, `diff`, `report`)
- **Backend** — Python/FastAPI + Celery workers
- **Frontend** — React 19 + TypeScript
- **Infrastructure** — Docker Compose, Kubernetes/Helm manifests

The question is whether these components should live in one repository (monorepo) or separate repositories (polyrepo).

---

## Decision

**Monorepo** — a single repository with clearly separated top-level directories per component.

### Proposed Directory Structure

```
cipherradar/
├── cli/                  # Go binary (cbom scan, diff, report)
│   ├── cmd/
│   ├── internal/
│   └── go.mod
│
├── backend/              # Python/FastAPI + Celery workers
│   ├── api/
│   ├── workers/
│   ├── analysis/
│   └── pyproject.toml
│
├── frontend/             # React 19 + TypeScript
│   ├── src/
│   └── package.json
│
├── scanner/              # Shared detection assets (CLI + backend)
│   ├── rules/            # Semgrep YAML rules (per language)
│   ├── library-models/   # Crypto API → CBOM asset type mappings (JSON/YAML)
│   └── grammars/         # tree-sitter grammar configs
│
├── deploy/               # Infrastructure
│   ├── docker-compose.yml
│   ├── k8s/
│   └── helm/
│
├── docs/                 # Design documentation and ADRs
│
└── .github/
    └── workflows/
        ├── cli.yml       # Triggers on cli/** or scanner/** changes
        ├── backend.yml   # Triggers on backend/** or scanner/** changes
        └── frontend.yml  # Triggers on frontend/** changes
```

---

## Rationale

### The Deciding Factor — Shared Detection Assets

The CLI and the backend scanner workers both require the same artifacts:

- **Semgrep YAML rules** — per-language taint rules (Pass 2 of detection engine)
- **Library API models** — crypto function signatures → CBOM asset type mappings
- **tree-sitter grammar configs** — shared parser configuration

In a polyrepo setup, these would require a third `cbom-rules` repository that must be versioned and kept in sync across two consumers. Any rule update requires a coordinated release across three repos. In a monorepo, it is a single `scanner/` directory referenced by both CLI and backend — one commit updates both.

### Additional Factors

| Factor | Detail |
|---|---|
| **CLI ↔ Backend coupling** | API contract changes (OpenAPI spec) must be reflected in both CLI client code and backend server. Atomic commits in a monorepo enforce this consistency. |
| **Phase-gated delivery** | Phases 1–5 deliver CLI + backend + frontend as coordinated releases. Cross-repo PRs and release coordination add friction with no benefit at this stage. |
| **Small team** | Polyrepo overhead (separate issue trackers, CI configs, access control, dependency version pinning) scales with team size. At current team size the overhead is not justified. |
| **Unified issue tracking** | A single repo means a single GitHub Issues list. Crypto findings, scanner bugs, and dashboard UI issues are all related — separating them into four trackers creates unnecessary navigation overhead. |
| **Shared docs** | All design documentation lives in `/docs`. A monorepo keeps docs, code, and ADRs co-located and versioned together. |

---

## Alternatives Considered

### Polyrepo (one repo per component)

Rejected. Requires:
- A fourth `cbom-rules` repo for shared detection assets
- Cross-repo PR coordination for any change touching CLI + backend
- Duplicated CI configuration across repos
- Version pinning and compatibility matrix between repos

Polyrepo is appropriate when teams are large enough that independent release cadences are a hard requirement, or when a component is maintained by a separate team. Neither condition applies at this stage.

### Separate repo for `scanner/` rules only

Partially considered as a middle ground. Rejected because:
- Still requires the same version pinning and sync problem between CLI and backend consumers
- No meaningful benefit over the monorepo approach for a single team

---

## Consequences

- **Positive:** Shared detection rules updated once, consumed by both CLI and backend in the same commit
- **Positive:** API contract changes are atomic — CLI client code and backend server code change together
- **Positive:** Single issue tracker, single PR history, single docs location
- **Positive:** Path-based CI triggers (`on: paths: ['cli/**']`) mean CI only runs what changed — no performance penalty
- **Negative:** Developers need to be aware of which component they are working in (mitigated by clear top-level directory separation)
- **Negative:** `git clone` fetches all components — acceptable at current codebase size; revisit if repo exceeds ~5GB

## When to Revisit

Reconsider splitting into polyrepo if any of the following occurs:

- The `scanner/rules` library matures into a standalone open-source project with external contributors
- A separate team is onboarded to own the CLI independently (e.g. open-source community)
- The Joern integration grows into a persistent microservice with its own independent release cycle

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/02-architecture.md` | No structural change; directory layout can be referenced in deployment section |
| `docs/08-roadmap.md` | No change to phases; repo structure is an implementation detail |
