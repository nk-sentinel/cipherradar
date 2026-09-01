# Decision Log

This document is the **central index of all architectural decisions** made during the design of CipherRadar. Each decision is recorded as an Architecture Decision Record (ADR) in `docs/decisions/`.

It also serves as a **change history** — recording what was originally decided, what was challenged, and what changed and why. The goal is that any new team member or stakeholder can read this log and understand the reasoning and evolution of the project design without needing to re-litigate settled questions.

---

## How to Read This Log

- **Accepted** — current standing decision; in effect
- **Superseded** — replaced by a later decision; kept for history
- **Proposed** — under discussion; not yet finalised

When a decision changes, the original ADR is kept and marked **Superseded**, and a new ADR is created that explicitly references it. Documents that are affected by the change are updated with a version header and change history table at the top.

---

## Decision Index

| ADR | Title | Status | Date | Affects |
|---|---|---|---|---|
| [ADR-001](decisions/ADR-001-output-format.md) | Output Format — CycloneDX 1.7 CBOM | Accepted | 2026-03-15 | All output |
| [ADR-002](decisions/ADR-002-parsing-backbone.md) | Parsing Backbone — tree-sitter | Accepted | 2026-03-15 | Detection engine, tech stack |
| [ADR-003](decisions/ADR-003-codeql-independence.md) | CodeQL Independence — No Build Required | Accepted | 2026-03-15 | Detection engine, architecture |
| [ADR-004](decisions/ADR-004-taint-engine-revision.md) | Taint Engine — Revised to Joern + OpenGrep | **Accepted** (supersedes original design) | 2026-03-16 | Detection engine v2, tech stack v2, roadmap v2 |
| [ADR-005](decisions/ADR-005-cli-language-and-deployment.md) | CLI Language — Go; Backend — Python/FastAPI | Accepted | 2026-03-15 | Tech stack, deployment |
| [ADR-006](decisions/ADR-006-rbac-design.md) | RBAC Design — 7 Roles (was 6), Permissions, API Key Model | Accepted | 2026-03-16 | `docs/09-rbac.md` |
| [ADR-007](decisions/ADR-007-communications-design.md) | Communications Design — Channels, Triggers, Notification Routing | Accepted | 2026-03-16 | `docs/10-communications.md` |
| [ADR-008](decisions/ADR-008-repository-structure.md) | Repository Structure — Monorepo | Accepted | 2026-03-18 | Repo layout, CI/CD |
| [ADR-009](decisions/ADR-009-opengrep-replaces-semgrep.md) | Pass 2 Engine — OpenGrep replaces Semgrep | Accepted | 2026-03-18 | `docs/03-detection-engine.md`, `docs/07-tech-stack.md`, ADR-004 |
| [ADR-010](decisions/ADR-010-cli-distribution-and-asset-embedding.md) | CLI Distribution — Two flavors, install-tools, embedded shared assets | Accepted | 2026-03-18 | `docs/07-tech-stack.md`, `CLAUDE.md` |
| [ADR-011](decisions/ADR-011-joern-integration-model.md) | Joern Integration Model — Subprocess Execution | Accepted | 2026-03-19 | `docs/07-tech-stack.md`, `docs/12-phase2-implementation-plan.md` |
| [ADR-012](decisions/ADR-012-backend-database-schema.md) | Backend Database Schema — CBOMStore, TimescaleDB Hypertables, JSONB Strategy | Accepted | 2026-03-19 | `docs/02-architecture.md`, `docs/12-phase2-implementation-plan.md` |
| [ADR-013](decisions/ADR-013-authentication-model.md) | Authentication Model — JWT + API Keys + Scoped Permissions | Accepted | 2026-03-19 | `docs/09-rbac.md`, `docs/12-phase2-implementation-plan.md` |
| [ADR-014](decisions/ADR-014-git-provider-abstraction.md) | Git Provider Abstraction — Common Interface for GitHub/GitLab/Bitbucket | Accepted | 2026-03-19 | `docs/12-phase2-implementation-plan.md` |
| [ADR-015](decisions/ADR-015-frontend-architecture.md) | Frontend Architecture — React 19, TanStack, Theme System | Accepted | 2026-03-19 | `docs/12-phase2-implementation-plan.md` |
| [ADR-024](decisions/ADR-024-cli-binary-rename.md) | CLI Binary Rename — cbom → cradar | Accepted | 2026-03-20 | `CLAUDE.md`, `README.md`, `deploy/`, `docs/08-roadmap.md` |
| [ADR-025](decisions/ADR-025-cli-portal-push.md) | CLI-to-Portal Push Model — `--push` flag + `.cradar.yml` config | Accepted | 2026-03-20 | `docs/13-phase3-implementation-plan.md`, `deploy/` |
| [ADR-026](decisions/ADR-026-binary-scanning-architecture.md) | Binary Scanning Architecture — Hybrid (Go byte-patterns + YARA-X) | Accepted | 2026-03-22 | `docs/03-detection-engine.md`, `docs/07-tech-stack.md`, ADR-010 |
| [ADR-027](decisions/ADR-027-llm-provider-abstraction.md) | LLM Provider Abstraction — Multi-provider with Anthropic default | Accepted | 2026-03-22 | `docs/07-tech-stack.md`, `docs/02-architecture.md` |
| [ADR-028](decisions/ADR-028-opentelemetry-runtime-enrichment.md) | OpenTelemetry Runtime Enrichment — Collector Exporter Plugin | Accepted | 2026-03-22 | `docs/02-architecture.md`, `docs/07-tech-stack.md` |
| [ADR-029](decisions/ADR-029-vscode-extension-architecture.md) | VS Code Extension — Direct Diagnostic Provider | Accepted | 2026-03-22 | `docs/08-roadmap.md`, `docs/07-tech-stack.md` |
| [ADR-030](decisions/ADR-030-intellij-plugin-architecture.md) | IntelliJ Plugin — External Annotator | Accepted | 2026-03-22 | `docs/08-roadmap.md`, `docs/07-tech-stack.md` |
| [ADR-031](decisions/ADR-031-cryptographic-agility-score.md) | Cryptographic Agility Score — 5-Factor Model | Accepted | 2026-03-22 | `docs/02-architecture.md`, `docs/06-compliance.md` |
| [ADR-032](decisions/ADR-032-hndl-risk-model.md) | HNDL Risk Model — Mosca Inequality + Multiplicative Score | Accepted | 2026-03-22 | `docs/06-compliance.md`, `docs/03-detection-engine.md` |
| [ADR-033](decisions/ADR-033-remove-joern-pass3.md) | Remove Joern (Pass 3) — All patterns covered by OpenGrep taint rules | Accepted | 2026-03-23 | `docs/03-detection-engine.md`, ADR-004, ADR-011 |
| [ADR-034](decisions/ADR-034-finding-identity-matching.md) | Finding Identity & Cross-Scan Matching — Normalized code fingerprint | Accepted | 2026-03-26 | D14, D15, D16, D21, D28, `cli/internal/scanner/`, `backend/app/services/` |
| [ADR-035](decisions/ADR-035-rule-lifecycle-and-deprecation-policy.md) | Rule Lifecycle & Deprecation Policy — category/maturity/default_enabled/noise_risk | Accepted | 2026-04-15 | `cli/internal/rulefilter/`, `cli/internal/explain/`, `scanner/rules/` |
| [ADR-036](decisions/ADR-036-structured-logging-and-exit-codes.md) | Structured Logging, Redaction Defaults, Exit-Code Contract | Accepted | 2026-04-15 | `cli/pkg/log/`, `cli/internal/cmd/exitcode.go`, `cli/internal/validation/validator.go` |
| [ADR-037](decisions/ADR-037-multi-output-and-format-dispatch.md) | Multi-Output Sinks, Extension Dispatch, TTY-Aware Defaults | Accepted | 2026-04-15 | `cli/internal/output/dispatch.go`, `cli/internal/output/table.go`, `cli/internal/cmd/scan.go`, `cli/internal/cmd/report.go` |
| [ADR-038](decisions/ADR-038.md) | Installer Checksum Verification — SHA-256 of downloaded tool binaries | Accepted | 2026-05-18 | `cli/internal/tools/checksum.go`, `cli/internal/tools/installer.go` |
| [ADR-039](decisions/ADR-039-yarax-binary-scanning.md) | YARA-X Integration for Binary Crypto Detection (Pass 3, opt-in) | Accepted | 2026-05-24 | `cli/internal/scanner/yarax/`, `scanner/yara-rules/`, `docs/08-roadmap.md`, ADR-026, ADR-038 |
| [ADR-040](decisions/ADR-040-library-asset-type.md) | Library detections emit as CycloneDX `type=library` components | Accepted | 2026-05-25 | CBOM output, CycloneDX converter |
| [ADR-041](decisions/ADR-041-keystore-password-policy.md) | Keystore inspection & default-password policy | Accepted | 2026-06-21 | `cli/internal/scanner/keystore/`, ADR-040 |
| [ADR-042](decisions/ADR-042-container-scan-materialization.md) | Container image scanning — materialize layers, reuse the directory walker | Accepted | 2026-09-01 | `cli/internal/container/`, gh #83, ADR-004, ADR-026, ADR-039 |
| [ADR-043](decisions/ADR-043-external-ast-rules.md) | External Pass-1 (AST) detection rules (`--ast-rules-dir`) | Accepted | 2026-09-01 | `cli/internal/scanner/astrules/`, `scanner/ast-rules/`, gh #114, ADR-004, ADR-009, ADR-039 |

> **Note on ADR-033:** ADR-033 (Remove Joern Pass 3) is recorded in the timeline section below under 2026-03-23 and supersedes the Pass 3 design from ADR-004 / ADR-011. It is listed here for index completeness:

| [ADR-033](decisions/ADR-033-remove-joern-pass3.md) | Remove Joern (Pass 3) — All patterns covered by OpenGrep taint rules | Accepted | 2026-03-23 | `docs/03-detection-engine.md`, `docs/08-roadmap.md`, ADR-004, ADR-011 |

---

## Timeline of Key Decisions and Changes

### 2026-03-15 — Initial Architecture Session

The following decisions were made during the initial product design and architecture session:

**ADR-001: CycloneDX 1.7 as output format**
CycloneDX 1.7 selected over custom JSON, SPDX 3.0, and CycloneDX 1.6. Primary reason: only format with a formally specified `cryptoProperties` schema covering all four asset types and native `nistQuantumSecurityLevel` field. Ratified as ECMA-424 2nd Edition.

**ADR-002: tree-sitter as the parsing backbone**
tree-sitter selected over per-language native parsers and ANTLR. Primary reason: 40+ language grammars via a single C library with a unified query API — adding language #13 costs minimal effort. Language-native semantic analysis layered on top only for Java, Kotlin, C#, and TypeScript where type resolution matters.

**ADR-003: No dependency on CodeQL; no build required**
Decision: CipherRadar must work on any codebase without a build step. Rationale: 80–85% of crypto API calls use direct string literals or single-hop variables — visible in source with no compilation. Requiring a build would block adoption on legacy, incomplete, or build-complex codebases. CodeQL may be added as an optional `--deep-scan` integration in Phase 4 but must never be a requirement.

**ADR-005: Go CLI + Python backend**
Go for the CLI binary (single static binary, no runtime dependencies, fast parallel scanning). Python/FastAPI for the backend API and reporting layer (richer ecosystem for data transformation and PDF generation).

**Original Detection Engine Design (v1)**
Detection engine designed with three components: tree-sitter, a custom taint engine, and a regex layer. *Note: this was revised — see ADR-004 below.*

---

### 2026-03-16 — Feasibility Challenge and Detection Engine Revision

**Challenge raised:** During architecture review, a feasibility question was raised about the "custom taint engine" component of the original detection engine design:

> *"Was a feasibility analysis done on this? How confident are you to create this, and how accurate do you expect it to be?"*

**Analysis conducted:** The term "taint engine" covers a wide spectrum from constant propagation (weeks to build) to full inter-procedural program-wide analysis (years to build, what SonarQube/CodeQL implement). The original design did not specify which level was intended and had no feasibility assessment.

Key findings from the analysis:
1. For CBOM generation, the "source" is always a string/integer literal — this is constant propagation, not general taint analysis
2. ~80–85% of real-world crypto API calls use direct literals or single-hop variables — all resolvable by a simple constant propagation pass
3. Two mature open-source tools already solve the harder cases: **Joern** (full CPG-based inter-procedural analysis, Apache 2.0) and **Semgrep** (declarative taint rules, LGPL)
4. Building a custom taint engine from scratch for 12 languages would take an estimated 6–12 months and would likely be less accurate than the existing tools

**ADR-004: Custom taint engine replaced with three-layer approach**
- Pass 1: tree-sitter + constant propagation — covers ~80% of findings, runs in seconds
- Pass 2: OpenGrep taint rules (YAML, per language) — covers ~8–10% additional findings, runs in minutes, runs on every PR
- Pass 3: Joern CPG analysis — covers ~3–5% additional hard cases, runs nightly

**Documents updated following ADR-004:**

| Document | Version Before | Version After | What Changed |
|---|---|---|---|
| `docs/03-detection-engine.md` | v1 | v2 | Full revision — custom taint engine replaced with three-layer approach; accuracy expectations revised; Joern and Semgrep sections added |
| `docs/07-tech-stack.md` | v1 | v2 | Custom taint engine entry replaced with Pass 1/2/3 entries; Joern and Semgrep added with rationale |
| `docs/08-roadmap.md` | v1 | v2 | Phase 1: "custom taint engine" → "constant propagation + Semgrep rules"; Phase 2: Joern integration added |

---

### 2026-03-18 — CLI Distribution Model and Shared Asset Embedding

**ADR-010: Two CLI flavors + embedded shared assets**
The CLI ships in two flavors: `cradar` (lightweight, ~15 MB, no tools bundled) and `cradar-full` (all-inclusive, ~80–100 MB, OpenGrep + Joern pre-bundled) for air-gapped/firewall environments (renamed from `cbom`/`cbom-full` per ADR-024). A `cradar install-tools` command covers internet-accessible users who want the lightweight binary but full scan coverage. Shared data assets (quantum algorithm table, library API models) live in `scanner/library-models/` as the single source of truth and are embedded into the CLI binary (`//go:embed`) and backend Python package at build time — ensuring air-gapped compatibility and version consistency between CLI and backend.

---

### 2026-03-18 — Pass 2 Engine: OpenGrep replaces Semgrep

**ADR-009: OpenGrep replaces Semgrep as the Pass 2 engine**
In December 2024, Semgrep Inc. moved taint analysis — the core feature required for Pass 2 — to their commercial tier, and placed the Semgrep Rules Registry under a licence that prohibits use in SaaS or competing products. In January 2025, OpenGrep was forked from Semgrep v1.100.0 by a consortium of 10+ AppSec companies, restoring taint mode under LGPL-2.1 with identical YAML rule format. CipherRadar switches to OpenGrep: taint mode remains free, there is no commercial rule licence conflict, and all `scanner/rules/` YAML files are fully compatible with no migration work.

---

### 2026-03-18 — Repository Structure Decision

**ADR-008: Monorepo**
Single repository with top-level directories for `cli/`, `backend/`, `frontend/`, `scanner/`, `deploy/`, and `docs/`. The deciding factor was the `scanner/` directory — shared OpenGrep rules, library API models, and tree-sitter configs are consumed by both the CLI and the backend scanner workers. A polyrepo setup would require a separate versioned `cbom-rules` repo and cross-repo coordination for every rule update. Path-based CI triggers (`on: paths:`) ensure builds only run for changed components. Revisit if the rules library becomes a standalone open-source project or a separate team is onboarded to own the CLI.

---

### 2026-03-18 — Phase 1 Implementation Complete

All 6 milestones (M1–M6) delivered. The CLI binary (now `cradar`, per ADR-024) scans Python, JavaScript/TypeScript, and Java codebases for cryptographic assets, outputting CycloneDX 1.7 JSON, SARIF 2.1, text summaries, and PDF reports. Key capabilities: 3-language tree-sitter scanning with constant propagation (Pass 1), OpenGrep taint rule integration (Pass 2, 16 rules embedded), regex and config file scanning, YAML policy engine with CI/CD exit codes, CBOM diff, parallel file scanning, CycloneDX 1.7 schema validation, GitHub Actions and GitLab CI templates.

**Deviations from original tech stack:**
- `cyclonedx-go` was not used — CycloneDX output implemented via internal structs in `cli/internal/cyclonedx17/` and `cli/internal/output/converter.go` (cyclonedx-go only supports 1.6; building internally was simpler than wrapping it)
- Koanf v2 was not used for config — `gopkg.in/yaml.v3` used directly for policy YAML parsing (simpler for single-file config)
- `santhosh-tekuri/jsonschema/v6` added for CycloneDX 1.7 schema validation
- `maroto/v2` added for PDF report generation

---

### 2026-03-19 — RBAC Update: Team Manager Role

**ADR-006 updated: Team Manager role added**
A 7th role ("Team Manager") was added to the RBAC model during UI mockup review. The role provides group-scoped read access + scan triggering for engineering managers and team leads — filling the gap between Developer (too limited for visibility) and Security Manager (too powerful for non-security leadership). Team Managers cannot configure policies, suppress findings, or approve suppression requests.

**ADR-011: Joern Integration Model — Subprocess Execution**
Joern (Apache 2.0, JVM/Scala) is integrated as a subprocess, the same pattern used for OpenGrep in Pass 2. Binary discovery follows the same resolution order (same dir → `$CRADAR_TOOLS_DIR` → `~/.cradar/tools/` → `$PATH`; renamed from `$CBOM_TOOLS_DIR`/`~/.cbom/tools/` per ADR-024). Persistent server mode and containerized deployment were evaluated but rejected: subprocess is simpler, consistent with the existing OpenGrep pattern, and the 5-10s JVM cold start is acceptable since Pass 3 runs nightly. The `cradar-full` binary bundles Joern alongside OpenGrep. Resolves OQ-002.

**ADR-012: Backend Database Schema — CBOMStore, TimescaleDB Hypertables, JSONB Strategy**
The backend database schema formalises four design decisions: (1) a `CBOMStore` abstraction with two implementations — `PostgresCBOMStore` for dev/early stage (< 10 GB, < 500 scans/day) and `S3CBOMStore` for production, swappable via config; (2) TimescaleDB hypertables for the `scan_metrics` table, enabling efficient time-range queries, automatic compression, and continuous aggregates; (3) JSONB columns with GIN indexes for flexible crypto finding metadata that avoids rigid schema migrations; (4) a Graph Abstraction Layer (GAL) using PostgreSQL recursive CTEs in Phase 1–2 with a clean Neo4j migration path in Phase 3. Key tables: organisations, groups, projects, scans, cbom_documents, findings, scan_metrics, policy_sets, compliance_mappings. Implements the storage architecture from D-001 and A-001.

**ADR-013: Authentication Model — JWT + API Keys + Scoped Permissions**
Human users authenticate via JWT (15-min access token + 7-day refresh token) with login via email/password or SSO (SAML/OIDC). Machine users (CI/CD) use scoped API keys prefixed `cradar_sk_...` (renamed from `cbom_sk_...` per ADR-024), SHA-256 hashed at rest. Seven permission scopes defined (`scan:read/write`, `cbom:read/write`, `project:read/write`, `report:read`); `policy:write` excluded from API keys per OQ-RBAC-7. RBAC enforcement via middleware with 7 roles at org/group/project level. JWT revocation handled via Redis deny-list. Libraries: `python-jose` (JWT), `passlib` (bcrypt).

**ADR-014: Git Provider Abstraction — Common Interface for GitHub/GitLab/Bitbucket**
A `GitProvider` protocol abstracts OAuth, repo listing, webhook management, status checks, and PR comments across GitHub, GitLab, Bitbucket Cloud, and Bitbucket Data Center. Four concrete implementations behind a single interface — business logic never touches provider-specific APIs. Webhook signature verification mandatory for all providers (HMAC-SHA256 for GitHub/Bitbucket, token validation for GitLab). New providers added by implementing one interface with no changes to scan orchestration or notification logic.

**ADR-015: Frontend Architecture — React 19, TanStack, Theme System**
Frontend built with React 19 + TypeScript strict mode + Vite. TanStack Router for type-safe routing, TanStack Query for server state (no `useState` + `useEffect` fetch patterns). shadcn/ui + Tailwind CSS for accessible, owned components. Three themes (Radar/Crystal/Sentinel) via CSS custom properties — zero-runtime-cost switching, no conditional rendering per theme. RBAC enforced via route guards and conditional navigation. MSW for mock API development (C-M1/C-M2); real API integration at C-M3. API types auto-generated from OpenAPI spec via `openapi-typescript`.

---

### 2026-03-20 — CLI Binary Rename and Portal Push Model

**ADR-024: CLI binary rename — cbom → cradar**
The CLI binary is renamed from `cbom` to `cradar` to reflect the full product capability. The tool now does far more than CBOM generation: 12-language scanning with 3 detection passes, policy enforcement, compliance checking, CBOM diffing, report generation, and portal push. The name "cradar" is the natural abbreviation of CipherRadar and aligns the CLI with the product brand. `cbom` is retained as a legacy alias (symlink) during Phase 3 for backward compatibility. All documentation, CI templates, GitHub Actions, GitLab CI files, environment variables (`CBOM_*` → `CRADAR_*`), config files (`.cbom.yml` → `.cradar.yml`), and tools directories (`~/.cbom/tools/` → `~/.cradar/tools/`) are updated. GoReleaser artifacts change from `cbom`/`cbom-full` to `cradar`/`cradar-full`.

**ADR-025: CLI-to-portal push model**
A `--push` flag on `cradar scan` enables combined scan + upload in a single command for CI/CD pipelines. The `--project` flag (required with `--push`) identifies the target project by name. The `--group` flag (optional) specifies the group path, falling back to the user's default group. API key authentication provides org context. A `.cradar.yml` config file can store defaults to reduce CLI verbosity. The backend endpoint `POST /api/v1/scans/upload` handles project auto-resolution (auto-create if user has `project:write` permission) and group fallback with security-safe error messages (identical 404 for "not found" and "no access" — same pattern as GitHub's 404-not-403 for private repos).

**Documents updated following ADR-024 and ADR-025:**

| Document | What Changed |
|---|---|
| `CLAUDE.md` | All `cbom` command references → `cradar`; legacy alias note; `--push` flag added |
| `README.md` | Quick Start section updated; all command examples → `cradar` |
| `docs/08-roadmap.md` | Phase 4 deliverables: SonarQube full plugin added |
| `docs/13-phase3-implementation-plan.md` | A-M2: CLI rename + `--push` flag; B-M2: upload endpoint + project resolution |
| `deploy/README.md` | All CI/CD examples → `cradar`; `cbom-action` → `cradar-action` |
| `deploy/github-action/action.yml` | Binary build → `cradar`; scan commands → `cradar` |
| `deploy/github-action/release.yml` | Artifact names → `cradar`/`cradar-full` |
| `deploy/github-action/example-workflow.yml` | Workflow example → `cradar` |
| `deploy/gitlab-ci/` | File renamed `cbom-scan.gitlab-ci.yml` → `cradar-scan.gitlab-ci.yml`; all references → `cradar` |

---

### 2026-03-22 — Phase 4 Architecture Decisions

Seven ADRs accepted covering Phase 4 capabilities:

**ADR-026: Binary Scanning Architecture — Hybrid (Go byte-patterns + YARA-X)**
Two-tier binary scanning aligned with the CLI distribution model (ADR-010). The lightweight `cradar` binary uses pure Go byte-pattern matching with YAML-defined rules (~70% accuracy). The full `cradar-full` binary bundles YARA-X with the findcrypt-yara ruleset (~90%+ accuracy). Graceful degradation when YARA-X is unavailable. JAR files are decompiled via CFR subprocess; Python wheels are extracted and scanned with existing language scanners. `cradar-full` archive now bundles OpenGrep + Joern + YARA-X (~300 MB total).

**ADR-027: LLM Provider Abstraction — Multi-provider with Anthropic default**
Backend Python `LLMProvider` abstract class with three implementations: `AnthropicProvider` (default), `OpenAIProvider`, and `OllamaProvider` (air-gapped/self-hosted). Provider selected via `CRADAR_LLM_PROVIDER` config. Remediation cached by finding fingerprint. Code snippets sent only with explicit org-level opt-in consent flag.

**ADR-028: OpenTelemetry Runtime Enrichment — Collector Exporter Plugin**
Go-based OTel Collector exporter plugin that filters spans for TLS/crypto attributes (`tls.protocol.version`, `tls.cipher_suite`, `net.sock.peer.cert`) and POSTs enrichment data to `POST /api/v1/runtime/enrich`. Backend links runtime observations to static CBOM findings by service + algorithm.

**ADR-029: VS Code Extension — Direct Diagnostic Provider**
TypeScript extension using VS Code Diagnostic API directly (not LSP). Invokes `cradar scan --format sarif --file <path>` on file save. HoverProvider shows quantum status. CodeActionProvider offers LLM-assisted remediation via backend API. TreeView sidebar and StatusBar with finding count.

**ADR-030: IntelliJ Plugin — External Annotator**
Kotlin External Annotator following IntelliJ's threading model. `collectInformation()` on EDT, `doAnnotate()` on background thread with SARIF caching, `apply()` on EDT with gutter icons and tooltips. Quick-fix intentions link to LLM remediation. Plugin calls `cradar` CLI as subprocess.

**ADR-031: Cryptographic Agility Score — 5-Factor Model**
0–100 composite score per project: Call Site Concentration (20%), Abstraction Level (25%), Algorithm Diversity (15%), Key Management Centralisation (20%), Migration Readiness (20%). Tracked per-scan in TimescaleDB for time-series trending.

**ADR-032: HNDL Risk Model — Mosca Inequality + Multiplicative Score**
`HNDL_risk = data_sensitivity × quantum_vulnerability × time_factor` (continuous 0–1 score). Multiplicative model ensures quantum-safe findings correctly score 0.0. Mosca inequality urgency flag: `shelf_life + migration_time > quantum_timeline - current_year` triggers URGENT status. All parameters configurable (quantum deadline defaults to 2035).

**ADR-010 updated:** `cradar-full` archive now bundles 3 tools (OpenGrep, Joern, YARA-X); size target updated from ~80–100 MB to ~300 MB.

> **Superseded by ADR-033 (2026-03-23):** Joern was subsequently removed from the pipeline. Pass 3 is now opt-in YARA-X binary scanning (ADR-039), and `cradar-full` no longer bundles Joern. See the 2026-03-23 entry below.

---

### 2026-03-23 — ADR-033: Joern (Pass 3) Removed from the Detection Pipeline

**ADR-033: Remove Joern (Pass 3)**
The Pass 3 design from ADR-004 and ADR-011 (Joern CPG inter-procedural analysis, run nightly) was removed. An audit mapped every Joern query to an equivalent OpenGrep (Pass 2) taint rule, so the inter-procedural cases Joern was meant to cover are now handled by Pass 2 with no nightly JVM job, no ~300 MB bundle, and no JVM cold-start cost. Concretely: `joern` was dropped from `cradar install-tools`; the `--passes` default changed from `1,2,3` to `1,2`; `runPass3()` and the Joern import were removed from the scan command; pass validation now accepts `1,2` (with `3` re-purposed for binary scanning). The `cli/internal/joern/` package is retained in the source tree as archived reference but is **no longer imported or executed**. This supersedes the active-Pass-3 description in ADR-004, ADR-011, and the OQ-001/OQ-002 resolutions above (those rows are kept for history; Joern is no longer the mechanism that compensates for OpenGrep inter-file gaps — OpenGrep rules now cover them directly).

---

### 2026-05-24 — ADR-039: YARA-X Binary Scanning (Pass 3, opt-in)

**ADR-039: YARA-X integration for binary crypto detection**
With Joern removed, the Pass 3 slot is re-purposed for opt-in binary scanning. YARA-X (`yr`) is wired into the scan pipeline as a binary-content scanner in `cli/internal/scanner/yarax/`, discovered via the same lookup order as OpenGrep and soft-skipped when absent (matching lite installs). An embedded ruleset lives at `scanner/yara-rules/*.yar` (OpenSSL version strings, libsodium/BoringSSL/mbedTLS magic, embedded PEM blobs, RSA private-key markers, AES S-box / round-constant patterns). It registers for compiled-artifact extensions (`.so .dll .dylib .exe .class .jar .whl .a .o .wasm`) and runs in parallel with the existing native Go byte-pattern scanner (ADR-026). YARA-X is **opt-in** — enabled via `--passes 1,2,3` or `--deep`. The YARA-X download path inherits the SHA-256 verification pattern established by ADR-038.

---

### 2026-06-23 — Expanded crypto-library inventory + enrichment

Cross-language Pass-2 library import rules extended to cover Spring/JWT/Jasypt/
Tink (Java), jose/@noble (JS/TS), passlib/PyJWT (Python), RustCrypto crates,
and related supply-chain libraries. `cli/internal/deps` enrichment now resolves
Maven `<dependencyManagement>` versions and Gradle `libs.versions.toml` catalog
aliases. Documented in [ADR-040 addendum](decisions/ADR-040-library-asset-type.md),
[CBOM schema reference §2.1](guides/cli/cbom-schema-reference.md), and
[06-data-model.md](06-data-model.md) v3.

---

### 2026-05-29 — Recall & Quantum-Coverage Expansion (issue #34)

Expanded quantum-vulnerable family coverage landed across the language scanners and the shared quantum-readiness table (`cli/internal/scanner/quantum/quantum-readiness.yml`): added detection for SM2, ECIES, GOST (8 languages), Schnorr (BIP-340), and BLS12-381, plus classification entries for ECMQV, Paillier, Rabin, EC-GDSA, and EC-KCDSA. Pass-2 (OpenGrep) findings now carry quantum posture, and inventory-only scans return a complete asset list including weak algorithms. Per-language detection coverage is tracked authoritatively in `docs/quantum-coverage-matrix.md`.

---

### 2026-05-25 — ADR-040: Library detections emit as type=library components

**ADR-040: Library detections emit as CycloneDX type=library components**
OpenGrep + YARA-X library-presence findings (cbom-asset-type: library) no longer pass
the invalid value through to CycloneDX `cryptoProperties.assetType`. Routed to
component `type: library` per CycloneDX 1.7 spec. Breaking change for CBOM JSON consumers
that read `assetType: "library"`. See ADR-040.

### 2026-09-01 — ADR-042 & ADR-043: Container scan rewrite + external Pass-1 rules (v0.5.0-rc.1)

**ADR-042: Container image scanning — materialize layers, reuse the directory walker.**
The diverged in-memory container scanner (text-files-≤1 MB only, no Pass 2, no on-disk
path for `yr`, dishonest `PassesRun`) is replaced by extracting image layers to a temp
dir and running the shared directory walker over it — so `--container` gets Pass 1/2/3,
the native binary/JAR/wheel scanners, recursive archive unpacking, per-layer provenance,
and image config/history/labels ingestion. Resolves gh #83.

**ADR-043: External Pass-1 (AST) detection rules.** The ~90 hardcoded Go maps behind
Pass-1 detection are externalized as per-language YAML (embedded default, overridable via
`--ast-rules-dir` with per-language replace semantics), mirroring `--rules-dir` (Pass 2)
and the new `--yara-rules-dir` (Pass 3). Every pass now supports external rules, so a
downstream portal can serve the full rule set. Resolves gh #114. See
`docs/ast-rules-external-design.md`.

---

## Open Questions / Pending Decisions

The following items have been identified but not yet formally decided:

| # | Question | Context | Priority |
|---|---|---|---|
| OQ-001 | Should OpenGrep suffice or do we need Semgrep Pro? | OpenGrep has limitations on inter-file taint; Pro removes these | **Resolved** — OpenGrep only; Joern Pass 3 compensates for inter-file gaps that OpenGrep misses |
| OQ-002 | Joern JVM — how to deploy server-side? | JVM startup overhead; subprocess vs persistent server vs isolated container | **Resolved** — Subprocess execution; see ADR-011 |
| OQ-003 | C# deep analysis strategy — Joern doesn't support C# yet | Options: Roslyn, wait for Joern, CodeQL, or OpenGrep only | **Resolved** — OpenGrep (Pass 1+2) for Phase 2; formal checkpoint at Phase 3 planning to re-evaluate Joern C# support; if still unavailable, choose between Roslyn and CodeQL at that point |
| OQ-004 | CodeQL as optional Pass 4 in Phase 4? | Best accuracy but requires build; conflicts with ADR-003 for non-opt-in use | **Resolved** — Evaluate at Phase 4 planning using real accuracy data from Pass 1–3; no commitment now |
| OQ-005 | Joern licensing in SaaS context? | Apache 2.0 — likely no restrictions | **Closed** — Not applicable; product is not currently planned as a commercial enterprise SaaS |
| OQ-RBAC-5 | Should suppression request expiry be mandatory or optional? | Mandatory expiry strengthens posture but may create noise for legitimate permanent suppressions | **Resolved** — Approver must set expiry or select "No expiry" explicitly; Developer comment mandatory with pre-submission validation |
| OQ-RBAC-6 | Should Guest/Viewer access require MFA, or is SSO token sufficient? | External auditors may not be in the org's IdP | **Resolved** — MFA optional per user; org-wide enforcement available; external MFA systems connectable |
| OQ-RBAC-7 | Should `policy:write` scope be available on API keys at all? | Restricting to UI-only prevents automated policy changes without human review | **Resolved** — Policy editing is UI-only; `policy:write` API scope removed |
| OQ-COMM-1 | SMS for certificate expiry alerts? | Adds telephony dependency | **Dropped** — Email + Teams sufficient |
| OQ-COMM-2 | PagerDuty/OpsGenie — Phase 3 or 4? | Enterprise on-call integration | **Resolved** — Phase 4 |
| OQ-COMM-3 | Webhook — single event or batched payload? | Custom integration design | **Deferred** — Phase 4; single-event default with optional scan-level batching |
| OQ-COMM-4 | Bi-directional Jira sync — Phase 3 or 4? | One-way is simpler for Phase 3 | **Resolved** — One-way Phase 3; bi-directional Phase 4 |
| A-001 | Graph DB: Neo4j vs PostgreSQL recursive CTEs? | Neo4j better at scale; PostgreSQL simpler operationally | **Resolved** — PostgreSQL CTEs Phase 1–2; Neo4j Phase 3 via Graph Abstraction Layer (GAL) as drop-in swap. Graph schema uses explicit nodes + edges tables from day one. See `docs/02-architecture.md` §2.4 |
| A-002 | Self-hosted deployment: Kubernetes only, or Docker Compose too? | Docker Compose needed for smaller enterprise teams without K8s | **Resolved** — Kubernetes (Helm) is the primary self-hosted and production deployment target. Docker Compose for development and testing. Standalone is documented but not a maintained deployment path. |
| A-003 | Git hosting scope: Azure DevOps and Bitbucket in scope? | Both widely used in enterprise; no mention in docs yet | **Resolved** — Phase 1 (CLI scan commands). Git hosting integrations (OAuth, webhooks, PR comments) moved to Phase 2. Azure DevOps and others added on demand based on customer need. |
| A-004 | Scan concurrency limits per org | Queue behaviour and per-tier limits undefined | **Resolved** — Concurrency limits are repo-level (default: 2 concurrent, 3 queue depth) with an org-level cap as infrastructure protection (tier-based default: 5/20/50). All limits configurable by Org Admin; setting to 0 disables that limit. Self-hosted orgs can set 0/0 for unlimited. Deduplication (same commit SHA already running or queued) always on — returns existing scan ID with `deduplicated: true`. Queue timeout default 10 minutes; configurable, 0 = no timeout. |
| D-001 | Data retention: how long are CBOM snapshots, scan history, audit logs kept? | GDPR, storage cost, compliance implications | **Resolved** — Default retention: CBOM snapshots 12 months, scan history 12 months, audit logs 24 months. All configurable by Org Admin. Hot/warm/cold model: hot 0–90 days (Postgres + TimescaleDB uncompressed), warm 90 days–12 months (TimescaleDB compressed + S3 Standard-IA), cold 12+ months (S3 Glacier). CBOM JSON stored in object storage (MinIO/S3), not Postgres — Postgres holds pointer. Dev/early stage: CBOM JSON in Postgres via `PostgresCBOMStore`; migrate to `S3CBOMStore` (MinIO) when storage exceeds ~10GB or scan volume exceeds ~500/day. CBOMStore interface abstracts both implementations as a drop-in swap. See `docs/02-architecture.md` §2.4. |
| D-002 | Data residency: SaaS multi-region (EU / US)? | EU CRA and GDPR may require EU data in EU | **Deferred** — On-premise only for initial rollout; customer owns their own infrastructure so residency is the customer's responsibility. Revisit when SaaS is planned. |
| D-003 | Right to deletion: can an org delete all scan data? | GDPR Article 17; customer churn | **Resolved** — Deletion supported at project, group, and org scope; cascades down the hierarchy. Repo disconnect offers retain or purge choice. All deletes are soft-delete first with 30-day grace period before hard purge. Org Admin can trigger immediate hard purge. Object storage (MinIO/S3) objects purged alongside DB records. |
| D-004 | Code snippet storage: store snippets in findings or file:line only? | Snippets help developers; storing source code is a trust/compliance concern | **Resolved** — Store snippet alongside finding. Default: 3 lines (1 above, finding line, 1 below). Configurable per org: 0 (file:line only), 3, 5, or 10 lines. Setting to 0 disables snippet storage entirely for orgs with strict code handling policies. |
| P-001 | Business model: open-source core + commercial, or fully commercial? | Not currently planned as commercial enterprise SaaS | **Deferred** — On-premise only for initial rollout; business model decision deferred until product is closer to ready. Architecture supports any model. |
| P-002 | SaaS pricing tiers: what features are gated at which tier? | Determines free vs. pro vs. enterprise feature split | **Deferred** — Depends on P-001 resolution; not relevant for on-premise initial rollout. |
| P-003 | API rate limits: scan submissions and API calls per org? | Abuse prevention; CI/CD pipeline design for large orgs | **Deferred** — Relevant only for SaaS/shared infrastructure; on-premise customers manage their own infra limits. Revisit when SaaS is planned. |
| S-001 | Dashboard session timeout and concurrent session policy | Platform security hygiene | **Resolved** — Idle timeout: 30 minutes default; absolute timeout: 8 hours default. Both configurable by Org Admin. Concurrent sessions: unlimited by default; Org Admin can set a maximum (e.g. 1 for strict orgs). New session beyond the limit kicks the oldest active session. |
| S-002 | Audit evidence package signing: PDF reports signed, or CBOM only? | Compliance Auditors may need signed PDFs for external audits | **Resolved** — Sign both CBOM (CycloneDX JSON/XML) and PDF compliance reports via Sigstore/cosign. SARIF remains unsigned (developer tool output, not a compliance artifact). Audit evidence package contains: signed CBOM + signed PDF + scan metadata + policy results. |
| S-003 | Vulnerability disclosure / security contact for CipherRadar itself | Security product credibility | **Deferred** — To be created before public release. Minimum: `security@[domain]` mailbox, `SECURITY.md` in repo root, 90-day coordinated disclosure policy, PGP key optional. Bug bounty deferred until public release. |

---

## Lessons Learned

### On Design Ambiguity

The "custom taint engine" incident illustrates a recurring risk in architecture documents: **compound terms that mean different things at different complexity levels**. "Taint engine" can mean a two-line regex or a decade of compiler research depending on context. Future design documents should specify the exact scope and complexity level of any component that involves analysis or inference.

### On Feasibility Challenges

The feasibility challenge on the taint engine was the right question to ask and saved significant engineering time. Architecture review should always ask for existing tools before proposing custom builds for any non-trivial infrastructure component.

### On Documenting Changes

This project adopted Architecture Decision Records (ADRs) from the start. When ADR-004 changed a core component, the impact on other documents was immediately clear from the ADR's "Impact on Other Documents" section. This made the update process systematic rather than ad-hoc.
