# Roadmap

> **Document version:** v7
> **Last updated:** 2026-03-20
> **Status:** Active

---

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-15 | Initial roadmap — Phase 1 included "custom taint engine" build | — |
| v2 | 2026-03-16 | Phase 1: taint engine → constant propagation + Semgrep rules. Phase 2: added Joern integration. | ADR-004 |
| v3 | 2026-03-17 | Phase 1: added GitHub, GitLab, Bitbucket (Cloud + Data Center) git hosting integrations | A-003 resolution |
| v4 | 2026-03-18 | Phase 1: Semgrep → OpenGrep (Pass 2 engine). Git hosting integrations moved to Phase 2 (require backend server). | ADR-009 |
| v5 | 2026-03-18 | Phase 1 complete — all checkboxes checked | Phase 1 close |
| v6 | 2026-03-20 | Phase 2 complete — 7 languages, backend API, React dashboard, Docker Compose full stack | Phase 2 close |
| v7 | 2026-03-20 | Phase 3 A-M1 + B-M1 + C-M1 + D-M1 complete: 12 languages, multi-tenant RBAC, Helm/K8s | Phase 3 Week 1-2 |

---

## Overview

Four phases, sequenced to deliver usable value at the end of each phase.

| Phase | Duration | Core Deliverable | Primary Users Enabled |
|---|---|---|---|
| Phase 1 — Foundation | Months 1–3 | CLI scanner, 3 languages, CycloneDX output | Individual developers, CI/CD pipelines |
| Phase 2 — Coverage + Risk | Months 4–6 | 7 languages, quantum scoring, compliance reports, REST API | Security architects, AppSec teams |
| Phase 3 — Enterprise | Months 7–9 | 12 languages, full compliance engine, dashboard, portfolio view | CISO, GRC teams, DevSecOps |
| Phase 4 — Differentiation | Months 10–12 | IDE plugins, binary scanning, LLM remediation, runtime enrichment | Full enterprise deployment |
| Phase 5 — Ecosystem & Intelligence | Months 13–18 | IaC scanning, git archaeology, AI triage, anomaly detection, CBOM federation | Enterprise portfolio, GRC, supply chain |

---

## Phase 1 — Foundation (Months 1–3)

**Goal:** A working CLI tool that a developer can run locally or in CI/CD in under 5 minutes.

### Deliverables

**Scanner Core**
- [x] tree-sitter integration with language detection and dispatch
- [x] AST-based detection for **Java, Python, JavaScript/TypeScript** (3 languages)
- [x] Library API model for: JCA/JCE, Bouncy Castle, `cryptography` (Python), `hashlib`, Node.js `crypto`, `jsonwebtoken`
- [x] Regex layer: PEM headers, key blobs, algorithm name strings
- [x] Config file scanner: `.env`, `*.properties`, basic YAML
- [x] **Pass 1: Constant propagation** — intra-procedural variable tracking + project-wide symbol table *(replaces "custom taint engine" from v1 — see ADR-004)*
- [x] **Pass 2: OpenGrep taint rules** — initial rule set for Java, Python, JS/TS covering common crypto patterns (OpenGrep replaces Semgrep per ADR-009)
- [x] Confidence scoring (High / Medium / Low / Unresolved)
- [x] File/line/column location for every finding

**Detection Coverage (Phase 1)**
- [x] Algorithms with name, mode, padding, key size
- [x] Hardcoded key material (constant → key parameter taint)
- [x] Static IV / nonce (constant → IV parameter taint)
- [x] Weak PRNG for security use
- [x] Disabled certificate validation
- [x] Deprecated TLS version (explicit config)

**Output**
- [x] CycloneDX 1.7 JSON — full `cryptoProperties` for all asset types
- [x] SARIF 2.1 output
- [x] Text summary output to terminal
- [x] PDF detailed report — per-finding breakdown, quantum status summary, severity distribution (Go: `maroto` library; Python backend uses ReportLab in Phase 2+)

**NIST Quantum Tagging**
- [x] `nistQuantumSecurityLevel` populated for all detected algorithms
- [x] `quantumStatus` tag: `quantum-vulnerable`, `quantum-safe`, `quantum-unknown`, `broken`

**Policy Engine (Basic)**
- [x] YAML policy file parsing
- [x] Rule evaluation: algorithm family, key size, TLS version
- [x] `PASS` / `FAIL` / `WARN` exit codes for CI/CD integration
- [x] `--fail-on CRITICAL` flag

**CI/CD**
- [x] GitHub Actions `cradar-action` — scan on push/PR; upload CBOM as artifact
- [x] GitLab CI template

**CLI Commands**
> Binary renamed from `cbom` to `cradar` per ADR-024. `cbom` available as legacy alias during Phase 3.

```bash
cradar scan ./path [--output cbom.json] [--format cyclonedx-json|sarif|text|pdf]
cradar scan <git-url> [--branch main]
cradar scan ./path --push --project "my-service" --api-key $CRADAR_API_KEY
cradar diff cbom-before.json cbom-after.json
cradar policy check cbom.json --policy policy.cradar.yml
cradar report cbom.json [--output report.pdf] [--format pdf]
```

**Success Criteria**
- Scans a 100k LOC Java project in < 5 minutes
- False positive rate < 10% for High/Critical findings
- CycloneDX 1.7 schema validation passes 100%

> Implementation plan, subagent breakdown, and skill assignments: see `docs/11-phase1-implementation-plan.md`

---

## Phase 2 — Coverage + Risk (Months 4–6)

**Goal:** Extend to more languages, add risk intelligence, and provide a basic API and web interface.

### Deliverables

**Language Expansion**
- [x] **Go** analyzer (stdlib `crypto/*`, `golang.org/x/crypto`)
- [x] **C#** analyzer (Roslyn, `System.Security.Cryptography`, BouncyCastle.NET)
- [x] **Kotlin** analyzer (reusing Java library model + Kotlin extensions)
- [x] **PHP** analyzer (`openssl_*`, `hash_*`, `password_hash`, `sodium_*`)
- [x] **Pass 3: Joern integration** — deep inter-procedural analysis for Java, Kotlin, Python, JS, C/C++ *(added in v2 per ADR-004; runs nightly)*

**Detection Expansion**
- [x] Certificate parsing from embedded PEM files
- [x] Certificate expiry checking
- [x] JWT/JOSE `alg` detection and `alg: none` flagging
- [x] PBKDF2 / bcrypt / scrypt / Argon2 iteration count checking
- [x] ECB mode detection
- [x] PKCS1v15 padding flagging

**Quantum Readiness**
- [x] Quantum Risk Score per repository (0–100)
- [x] Migration Priority Queue (ranked service list by quantum exposure)
- [x] PQC Readiness Report (PDF) — % quantum-safe, top migration targets

**Compliance Mapping**
- [x] NIST SP 800-131A Rev. 3 — Acceptable / Deprecated / Disallowed tagging
- [x] FIPS 140-3 compliance checks
- [x] Compliance gap report (PDF)

**CBOM Management**
- [x] CBOM versioning — every scan stored as an immutable snapshot
- [x] CBOM diff API — compare two scans
- [x] CBOM merge — aggregate multiple CBOMs into one

**Git Hosting Integrations** *(moved from Phase 1 — require backend server)*
- [x] GitHub — OAuth, webhooks, Checks API, PR review comments
- [x] GitLab — OAuth, webhooks, MR notes API
- [x] Bitbucket Cloud — OAuth, webhooks, PR comments API
- [x] Bitbucket Data Center — PAT auth, webhooks, REST API

**REST API + Basic UI**
- [x] FastAPI backend with OpenAPI 3.1 spec
- [x] Scan submission, status polling, results retrieval
- [x] Basic React dashboard: repository list, latest scan summary, finding list

**Success Criteria**
- 7 languages supported
- Compliance gap reports pass review by a GRC practitioner
- API response time < 200ms for CBOM retrieval

---

## Phase 3 — Enterprise (Months 7–9)

**Goal:** Full language coverage, complete compliance engine, portfolio-level dashboard, enterprise integrations.

### Deliverables

**Language Completion**
- [x] **C/C++** analyzer (OpenSSL, libsodium, mbedTLS — via Joern)
- [x] **Rust** analyzer (`ring`, `rustls`, `openssl` crate)
- [x] **Swift** analyzer (CryptoKit, CommonCrypto)
- [x] **Ruby** analyzer (OpenSSL, BCrypt, Digest)
- [x] **Dart/Flutter** analyzer (`package:crypto`, `pointycastle`)

**Detection Expansion**
- [ ] Container image layer scanning (OCI image → extract + scan filesystem)
- [ ] Config file expansion: nginx.conf, httpd.conf, openssl.cnf, java.security, k8s manifests, Dockerfiles
- [ ] SBOM ingestion + CBOM ↔ SBOM component linking

**Full Compliance Engine**
- [ ] PCI-DSS v4.0 compliance mapping
- [ ] NSA CNSA 2.0 compliance mapping + timeline tracker
- [ ] ISO 27001:2022 A.8.24 mapping
- [ ] EU Cyber Resilience Act gap report
- [ ] Compliance score (0–100 per framework per repository)
- [ ] Compliance score trending over time

**Dashboard (Full)**
- [ ] Portfolio dashboard — all repositories, heat map, quantum readiness %
- [ ] Asset explorer — searchable, filterable crypto inventory
- [ ] Algorithm distribution charts
- [ ] Dependency graph — interactive force-directed graph
- [ ] Certificate expiry calendar
- [ ] Compliance dashboard — per-framework scores with drill-down
- [ ] CBOM diff view — side-by-side snapshot comparison
- [ ] Migration Kanban board

**Enterprise Features**
- [x] Multi-tenant support with RBAC
- [ ] CBOM signing via Sigstore / cosign
- [ ] Jira integration — auto-create tickets on policy violation
- [ ] Slack / Teams notifications
- [ ] Dependency-Track integration
- [ ] SonarQube plugin (adds CBOM tab to SonarQube)
- [x] Self-hosted Docker / Kubernetes deployment package

**Success Criteria**
- 12 languages supported
- Portfolio of 50 repositories scannable within 30 minutes (parallel workers)
- SOC 2 Type II compliance for the SaaS platform

---

## Phase 4 — Differentiation (Months 10–12)

**Goal:** Features that separate CipherRadar from all other tools in the market.

### Deliverables

**Developer Tooling**
- [ ] VS Code extension — inline findings; hover for quantum status and remediation
- [ ] IntelliJ / JetBrains plugin — line-level annotations
- [ ] Pre-commit hook — fast regex scan; blocks hardcoded keys before commit

**Advanced Detection**
- [ ] Binary / JAR / Python wheel scanning for crypto constants (when source unavailable)
- [ ] "Harvest Now, Decrypt Later" risk model with data classification metadata integration
- [ ] Cryptographic Agility Score per service
- [ ] Custom source/sink configuration for in-house crypto wrappers

**LLM-Assisted Remediation**
- [ ] For each finding, generate a concrete code replacement in the correct language
- [ ] Context-aware: suggests the idiomatic fix for the detected library/framework
- [ ] Remediation previewed in dashboard and PR comments

**Runtime Enrichment**
- [ ] OpenTelemetry receiver — accepts runtime span data annotated with observed TLS versions and cipher suites
- [ ] Enriches static CBOM with actually-negotiated protocol parameters
- [ ] Highlights gaps between configured and observed crypto

**Attestation and Supply Chain**
- [ ] CBOM attestation via Sigstore — keyless signing; Rekor transparency log entry per scan
- [ ] SBOM ↔ CBOM CVE correlation — when a CVE is published for a crypto library, instantly show affected services
- [ ] OWASP MASVS compliance report (mobile security — aligned with CycloneDX mobile extensions)

**Enterprise Integrations**
- [ ] Full SonarQube plugin with CBOM tab + marketplace publishing (deferred from Phase 3 D-M3)

**Success Criteria**
- IDE plugins published to VS Code Marketplace and JetBrains Marketplace
- LLM remediation acceptance rate > 60% (developer accepts suggestion without modification)
- CBOM attestation verifiable via `cosign verify`

---

## Phase 5 — Ecosystem & Intelligence (Months 13–18)

**Goal:** Extend beyond static source scanning into infrastructure, history, team intelligence, and ecosystem participation.

### Deliverables

**Source History & Infrastructure**
- [ ] Git history crypto archaeology — full repo history scan, introduced-by attribution, delete vs. rotate detection
- [ ] Secrets longevity tracker — age-weighted severity via `git blame`
- [ ] IaC / cloud config scanning — Terraform, CloudFormation, Pulumi, Helm, Bicep, CDK crypto misconfig detection
- [ ] Inter-service crypto consistency checker — TLS/cipher mismatch detection across service pairs
- [ ] Protocol negotiation analysis — negotiable cipher suite weakness detection, `prefer_server_ciphers` analysis

**Quantum Migration Operations**
- [ ] Regulatory deadline burn-down dashboard — per-finding deadline mapping, velocity-based ETA, board-exportable
- [ ] Crypto migration project tracker — auto-create tasks, burn-down chart, Jira/Linear/GitHub Issues integration
- [ ] PQC algorithm compatibility matrix — per-service/language feasibility scoring (Ready / Needs upgrade / No path)

**Developer & Quality**
- [ ] Crypto test coverage analyzer — failure path coverage detection per crypto operation
- [ ] Crypto ownership heatmap — CODEOWNERS + git blame × finding count; per-team quantum readiness score
- [ ] Crypto API surface coverage score — endpoint → TLS config mapping, downgrade route detection
- [ ] Database encryption audit — ORM/migration file scanning for unencrypted sensitive columns

**AI & ML**
- [ ] AI-powered false positive triage — LLM contextual classification with human-readable rationale
- [ ] Crypto anomaly detection — ML on CBOM history; unexpected algorithm appearance; known malware signature matching

**Ecosystem**
- [ ] WASM / edge function scanning — WebAssembly bytecode crypto constant detection
- [ ] Mobile-specific deep scanning — Android/iOS network security config, ATS exceptions, certificate pinning
- [ ] Supply chain CBOM federation — publisher mode; CBOM attestation per release; downstream CBOM composition
- [ ] CBOM marketplace / public hub — OSS CBOM publishing, dependency CBOM subscriptions, community benchmarks

**Success Criteria**
- IaC scanning covers Terraform, CloudFormation, and Helm as minimum
- Git archaeology completes on a 5-year, 10k commit repo in < 10 minutes
- Crypto ownership heatmap auto-assigns tickets with < 5% wrong-team rate
- AI triage reduces false positive noise by > 30% vs. unfiltered output

---

## Dependency and Risk Notes

| Risk | Mitigation |
|---|---|
| tree-sitter grammar gaps for some languages | Maintain fallback regex layer; contribute to upstream grammars |
| Taint analysis precision vs. performance trade-off | Configurable depth limit; separate "deep scan" mode from "fast scan" mode |
| CycloneDX spec evolution | Official CycloneDX library abstracts schema changes; pin to library versions |
| LLM remediation quality | Human review always required; never auto-apply; clear labelling as "suggested" |
| C/C++ analysis speed (Joern) | Joern analysis is slow; run asynchronously; cache results per commit SHA |
