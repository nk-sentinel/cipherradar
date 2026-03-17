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
| [ADR-004](decisions/ADR-004-taint-engine-revision.md) | Taint Engine — Revised to Joern + Semgrep | **Accepted** (supersedes original design) | 2026-03-16 | Detection engine v2, tech stack v2, roadmap v2 |
| [ADR-005](decisions/ADR-005-cli-language-and-deployment.md) | CLI Language — Go; Backend — Python/FastAPI | Accepted | 2026-03-15 | Tech stack, deployment |
| [ADR-006](decisions/ADR-006-rbac-design.md) | RBAC Design — Roles, Permissions, API Key Model | Accepted | 2026-03-16 | `docs/09-rbac.md` |
| [ADR-007](decisions/ADR-007-communications-design.md) | Communications Design — Channels, Triggers, Notification Routing | Accepted | 2026-03-16 | `docs/10-communications.md` |
| [ADR-008](decisions/ADR-008-repository-structure.md) | Repository Structure — Monorepo | Accepted | 2026-03-18 | Repo layout, CI/CD |

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
- Pass 2: Semgrep taint rules (YAML, per language) — covers ~8–10% additional findings, runs in minutes, runs on every PR
- Pass 3: Joern CPG analysis — covers ~3–5% additional hard cases, runs nightly

**Documents updated following ADR-004:**

| Document | Version Before | Version After | What Changed |
|---|---|---|---|
| `docs/03-detection-engine.md` | v1 | v2 | Full revision — custom taint engine replaced with three-layer approach; accuracy expectations revised; Joern and Semgrep sections added |
| `docs/07-tech-stack.md` | v1 | v2 | Custom taint engine entry replaced with Pass 1/2/3 entries; Joern and Semgrep added with rationale |
| `docs/08-roadmap.md` | v1 | v2 | Phase 1: "custom taint engine" → "constant propagation + Semgrep rules"; Phase 2: Joern integration added |

---

### 2026-03-18 — Repository Structure Decision

**ADR-008: Monorepo**
Single repository with top-level directories for `cli/`, `backend/`, `frontend/`, `scanner/`, `deploy/`, and `docs/`. The deciding factor was the `scanner/` directory — shared Semgrep rules, library API models, and tree-sitter configs are consumed by both the CLI and the backend scanner workers. A polyrepo setup would require a separate versioned `cbom-rules` repo and cross-repo coordination for every rule update. Path-based CI triggers (`on: paths:`) ensure builds only run for changed components. Revisit if the rules library becomes a standalone open-source project or a separate team is onboarded to own the CLI.

---

## Open Questions / Pending Decisions

The following items have been identified but not yet formally decided:

| # | Question | Context | Priority |
|---|---|---|---|
| OQ-001 | Should Semgrep OSS suffice or do we need Semgrep Pro? | Semgrep OSS has limitations on inter-file taint; Pro removes these | **Resolved** — Semgrep OSS only; Joern Pass 3 compensates for inter-file gaps that OSS misses |
| OQ-002 | Joern JVM — how to deploy server-side? | JVM startup overhead; subprocess vs persistent server vs isolated container | **Resolved** — Defer deployment model decision to Phase 2 when Joern is actually being integrated; decide based on observed load and infra |
| OQ-003 | C# deep analysis strategy — Joern doesn't support C# yet | Options: Roslyn, wait for Joern, CodeQL, or Semgrep only | **Resolved** — Semgrep OSS (Pass 1+2) for Phase 2; formal checkpoint at Phase 3 planning to re-evaluate Joern C# support; if still unavailable, choose between Roslyn and CodeQL at that point |
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
| A-003 | Git hosting scope: Azure DevOps and Bitbucket in scope? | Both widely used in enterprise; no mention in docs yet | **Resolved** — GitHub, GitLab, and Bitbucket (Cloud + Data Center) in Phase 1. Azure DevOps and others added on demand based on customer need. |
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
