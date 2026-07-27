# Technology Stack

> **Document version:** v10
> **Last updated:** 2026-07-26
> **Change:** Keystore format coverage — JCEKS + BKS pure-Go cert readers, BCFKS/UBER/macOS Keychain/Mozilla NSS presence capture, project-harvested keystore passwords; certificate identity/context metadata (`cradar:cert:*`).

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-15 | Initial stack — listed "custom taint engine" under Language Parsers |
| v2 | 2026-03-16 | Replaced custom taint engine with Joern + Semgrep per ADR-004 |
| v3 | 2026-03-18 | Pass 2 engine changed from Semgrep OSS to OpenGrep per ADR-009 |
| v4 | 2026-03-18 | Viper → Koanf; Celery → Taskiq; CycloneDX Go library implementation note (stack audit) |
| v5 | 2026-03-18 | Two CLI distribution flavors; cbom install-tools; shared asset embedding via go:embed; module path confirmed |
| v6 | 2026-03-18 | Phase 1 actuals: yaml.v3 replaces Koanf; internal CycloneDX structs replace cyclonedx-go; jsonschema/v6 added; Docker images renamed | Phase 1 close |
| v7 | 2026-05-29 | **Detection engine Pass 3 changed.** Joern (CPG) removed entirely per [ADR-033](decisions/ADR-033-remove-joern-pass3.md); Pass 3 is now **YARA-X** binary content scanning per [ADR-039](decisions/ADR-039-yarax-binary-scanning.md). CLI binary renamed `cbom`→`cradar` and `cbom-full`→`cradar-full`; tools dir `~/.cbom`→`~/.cradar` per [ADR-024](decisions/ADR-024-cli-binary-rename.md). |
| v8 | 2026-06-21 | Added CLI subsystems: dependency/purl resolution (`deps`), keystore inspection (`keystore-go/v4`, `go-pkcs12`), shared cert builder (`certutil`, `hhrutter/pkcs7`), and scan ignores (`ignore`, `sabhiram/go-gitignore`). See §2.1. |
| v9 | 2026-06-23 | Expanded crypto-library inventory rules across 9 languages (Spring/JWT/Jasypt/Tink, jose/@noble, passlib/PyJWT, RustCrypto crates, etc.); `deps` now resolves Maven `<dependencyManagement>` and Gradle `libs.versions.toml` catalog aliases. See §2.1. |
| v10 | 2026-07-26 | Keystore inspection extended: pure-Go JCEKS + BKS cert readers; BCFKS/UBER/macOS Keychain/Mozilla NSS captured presence-only; project config/source keystore-password harvesting (coverage-only, never reported). Certificate parsing surfaces identity/context metadata (serial, SHA-256 fingerprint, SKI/AKI, curve, AIA/CRL, self-signed) as `cradar:cert:*` properties + `cbom-cert-unparsed`. See the [ADR-041 addendum](decisions/ADR-041-keystore-password-policy.md). |

---

## 1. Design Principles for Technology Choices

- **Single binary CLI** — zero dependencies for the developer-facing tool
- **Tree-sitter as the parsing backbone** — 40+ language grammars via one C library; language plugins are cheap to add
- **Open standards output** — CycloneDX 1.7, SARIF 2.1, SPDX 3.0; no proprietary formats
- **Language-agnostic API** — all functionality exposed via REST API; the UI is just a client

---

## 2. Stack Breakdown

### 2.1 CLI Tool

| Component | Technology | Rationale |
|---|---|---|
| Language | **Go** | Single binary distribution; fast; memory-safe; excellent concurrency for parallel file scanning |
| Module path | `github.com/nk-sentinel/cipherradar/cli` | Binary not library; no vanity domain needed |
| Build/dist | GoReleaser | Two flavors: `cradar` (lightweight, ~15 MB) and `cradar-full` (bundled OpenGrep + YARA-X, ~80–100 MB); cross-platform (macOS, Linux, Windows); checksums; GitHub Releases. See [ADR-024](decisions/ADR-024-cli-binary-rename.md) |
| Tool installation | `cradar install-tools` subcommand | Downloads OpenGrep + YARA-X (`yr`) from their GitHub Releases to `~/.cradar/tools/`; for lightweight binary users with internet access (Pass 3 / YARA-X requires `yr`) |
| Shared asset embedding | `//go:embed` | Quantum algorithm table and library API models from `scanner/library-models/` embedded at compile time; no runtime file dependency; works air-gapped |
| Config/policy parsing | **gopkg.in/yaml.v3** | Direct YAML parsing for `.cradar.yml` and `policy.cradar.yml`; lightweight, stdlib-compatible. Koanf v2 evaluated but deferred — yaml.v3 sufficient for Phase 1 |
| Output | Internal `cyclonedx17/` + `output/converter.go` | Custom CycloneDX 1.7 structs for full cryptoProperties support. `cyclonedx-go` evaluated but not adopted (supports 1.6 only; PR #257 stalled). Backend uses `cyclonedx-python-lib` v11.7.0 natively |
| Schema validation | **santhosh-tekuri/jsonschema/v6** | CycloneDX 1.7 JSON Schema validation; official schema embedded via //go:embed |
| Dependency / purl resolution | `cli/internal/deps` | Parses manifests & lockfiles (npm, PyPI, Maven/Gradle incl. `dependencyManagement` + `libs.versions.toml`, Cargo, RubyGems, Go modules, Dart/pub) to resolve a detected crypto library to an exact version + purl via `library_map.go` token mapping. Composer/NuGet detection is rule-only until ecosystem parsers land. No external deps |
| Keystore inspection | `cli/internal/scanner/keystore` + **pavlo-v-chernykh/keystore-go/v4**, **software.sslmate.com/src/go-pkcs12** | Enumerate certs in JKS / PKCS#12 / **JCEKS** / **BKS** stores (JCEKS + BKS via pure-Go readers, no BouncyCastle JAR); curated default-password set **plus project-harvested passwords** (config keys + keystore-load calls, coverage-only); **BCFKS / UBER / macOS Keychain / Mozilla NSS captured presence-only** ([ADR-041 + 2026-07 addendum](decisions/ADR-041-keystore-password-policy.md)) |
| Certificate parsing | `cli/internal/scanner/certutil` + stdlib `crypto/x509`, **hhrutter/pkcs7** | Shared X.509 finding builder (PEM/DER/PKCS#7); public-key algo+size, validity, and KeyUsage/EKU/BasicConstraints/SAN extensions; identity/context metadata (serial, SHA-256 fingerprint, SKI/AKI, curve, AIA/CRL, self-signed) as `cradar:cert:*` properties; unparsed cert material surfaced (`cbom-cert-unparsed`) |
| Scan ignores | `cli/internal/scanner/ignore` + **sabhiram/go-gitignore** | Built-in default ignores + `.gitignore` / `.cradarignore` ([gh #46](https://github.com/nk-sentinel/cipherradar/issues/46)) |

### 2.2 Language Parsers

| Component | Technology | Rationale |
|---|---|---|
| Multi-language AST | **tree-sitter** (C library + Go bindings `go-tree-sitter`) | 40+ language grammars; battle-tested (used in Neovim, GitHub Copilot, Zed); single API across all languages |
| Java semantic analysis | JavaParser (Java library called via CGo or subprocess) | Resolves type information tree-sitter does not have; needed for full method signature resolution |
| Kotlin semantic analysis | Kotlin compiler API (via subprocess) | Official AST access with full type resolution |
| TypeScript type resolution | TypeScript Compiler API (Node.js subprocess) | Type information critical for resolving crypto interface implementations |
| Python AST | Python `ast` module (subprocess) | Native; accurate; handles Python 3.8–3.14 syntax evolution |
| **Pass 1: Constant propagation** | Custom implementation over tree-sitter CSTs | Intra-procedural variable tracking + cross-file symbol table; covers ~80% of CBOM use cases; see ADR-004 |
| **Pass 2: OpenGrep taint rules** | OpenGrep (LGPL-2.1) + 207 custom YAML rules (154 inventory + 53 security) across 12 files | Community fork of Semgrep v1.100.0; restores taint mode (moved to Semgrep commercial Dec 2024); identical YAML rule format; no SaaS/commercial licence restrictions; default pass; findings carry quantum posture; see [ADR-009](decisions/ADR-009-opengrep-replaces-semgrep.md) |
| **Pass 3: YARA-X binary scanning** | YARA-X (`yr`, Rust) via subprocess | Opt-in (`--deep`). Scans compiled artifacts for hard-coded keys, pinned certs, statically-linked crypto library banners, and algorithm byte tables (e.g. AES S-box). Replaced the prototyped-and-removed Joern CPG pass; see [ADR-033](decisions/ADR-033-remove-joern-pass3.md) (Joern removal) and [ADR-039](decisions/ADR-039-yarax-binary-scanning.md) (YARA-X) |

**Why tree-sitter over language-specific parsers for everything?**
tree-sitter provides: error-tolerant parsing (handles incomplete/broken code), incremental re-parsing (fast for diffs), and a unified CST query language (`(call_expression)`) across all languages. It is not semantically aware (no type resolution), but for the majority of crypto API detection — where we are matching call expressions against known library function names — this is sufficient. Semantic analysis is layered on top only where necessary.

### 2.3 Backend API Server

| Component | Technology | Rationale |
|---|---|---|
| Language | **Python (FastAPI)** | Async, fast, easy to write; excellent for the analysis/reporting layer which involves heavy data transformation |
| API spec | OpenAPI 3.1 (auto-generated by FastAPI) | Auto-generated; always in sync with implementation |
| Authentication | JWT (short-lived) + API keys (CI/CD) | Standard; stateless |
| Task queue | **Taskiq + Redis** | Async scanning of large repos; parallel worker scaling; replaces Celery (Taskiq is async-native, 5–8x faster in benchmarks, integrates directly with FastAPI, uses Redis Streams for reliability) |
| Background jobs | Taskiq scheduler | Scheduled re-scans; certificate expiry checks; compliance score recalculation |

### 2.4 Data Storage

| Store | Technology | Rationale |
|---|---|---|
| Primary CBOM store | **PostgreSQL 17** | ACID; JSONB for CycloneDX document storage; mature; row-level security for multi-tenancy |
| Time-series (trends) | **TimescaleDB** (PostgreSQL extension) | Scan history, compliance score trends, finding counts over time — hypertables with efficient time queries |
| Asset dependency graph | **PostgreSQL with recursive CTEs** (or Neo4j for large deployments) | Recursive CTE covers most graph queries; Neo4j for organisations with 100+ services and complex dependency graphs |
| Search / filter | PostgreSQL full-text search + GIN indexes | Algorithm/asset search across large CBOMs |
| Scan queue | **Redis** | Fast; Taskiq broker; ephemeral scan state |
| File cache | S3 / compatible object store | Store CBOM JSON artifacts + signed attestations |

### 2.5 Frontend Dashboard

| Component | Technology | Rationale |
|---|---|---|
| Framework | **React 19 + TypeScript** | Component model suits dashboard/data-heavy UI |
| Charting | **Recharts** + D3.js (for dependency graph) | Recharts for standard charts; D3 force-directed graph for crypto dependency visualisation |
| UI components | shadcn/ui + Tailwind CSS | Fast to build; accessible; no heavy design system lock-in |
| State management | TanStack Query (React Query) | Server state; cache; background refetch |
| Build | Vite | Fast dev server; optimised production builds |

### 2.6 Report Generation

| Component | Technology | Rationale |
|---|---|---|
| PDF reports (CLI) | **maroto** (Go) | Report-style PDFs from the CLI binary; no external dependencies; built on fpdf |
| PDF reports (backend) | **ReportLab** (Python) | Backend-generated reports (Phase 2+); full control over layout |
| HTML reports | **Jinja2** templates | Developer findings reports; lightweight |
| SARIF output | Python `sarif-om` library | Standards-compliant SARIF 2.1 output |
| CycloneDX output | `cyclonedx-python-library` | Official library; always spec-compliant |
| Excel / CSV | `openpyxl` + Python `csv` | Compliance gap reports for GRC teams |

### 2.7 CI/CD Integrations

| Integration | Technology |
|---|---|
| GitHub Actions | GitHub Actions YAML + GitHub Checks API (Go) |
| GitLab CI | GitLab CI YAML template + GitLab Security Dashboard SARIF upload |
| Jenkins | Jenkins plugin (Java — thin wrapper calling the CLI binary) |
| Pre-commit | Shell hook (thin wrapper calling `cradar scan --fast`) |
| VS Code extension | TypeScript + VS Code Language Server Protocol |
| IntelliJ plugin | Kotlin + IntelliJ Platform SDK |

### 2.8 Security Infrastructure

| Component | Technology |
|---|---|
| CBOM signing | **Sigstore / cosign** — keyless signing; Rekor transparency log |
| Secrets in transit | TLS 1.3 everywhere |
| Scanner sandbox | **gVisor (runsc)** — kernel-level isolation for scanning untrusted code |
| Container images | Distroless base images; non-root user; read-only filesystem |
| Dependency scanning (for CipherRadar itself) | Dependabot + OWASP Dependency-Check |

---

## 3. Architecture Decision: tree-sitter vs. Language-Native Parsers

The central technical decision in the detection engine.

| Approach | Pros | Cons |
|---|---|---|
| **tree-sitter** (chosen for primary parsing) | Single API for 40+ languages; error-tolerant; incremental; fast (C core) | No semantic/type information; can miss some indirect calls |
| Language-native parsers (JavaParser, Roslyn, etc.) | Full semantic resolution; type-aware | One per language; significant maintenance burden; compilation required |
| **Hybrid** (chosen overall) | tree-sitter handles the majority; semantic layer added per language for high-value targets | More complexity; two code paths |

**Decision:** Use tree-sitter as the primary parsing layer for all languages. Layer language-native semantic analysis on top specifically for Java, Kotlin, C#, and TypeScript where type resolution is critical for accurate crypto API identification. For all other languages, tree-sitter + the library API model provides sufficient accuracy.

---

## 4. Deployment Infrastructure

```yaml
# docker-compose.yml (self-hosted)
services:
  api:
    image: cipherradar/api:latest
    environment:
      - DATABASE_URL=postgresql://...
      - REDIS_URL=redis://redis:6379
    ports: ["8000:8000"]

  scanner-worker:
    image: cipherradar/scanner:latest
    runtime: runsc  # gVisor sandbox
    environment:
      - TASKIQ_BROKER=redis://redis:6379
    scale: 4  # parallel scanning workers

  frontend:
    image: cipherradar/frontend:latest
    ports: ["3000:3000"]

  db:
    image: timescale/timescaledb:latest-pg17
    volumes: ["pgdata:/var/lib/postgresql/data"]

  redis:
    image: redis:7-alpine

  minio:
    image: minio/minio:latest  # S3-compatible; for CBOM artifact storage
    volumes: ["minio-data:/data"]
```
