# Roadmap

> **Document version:** v4
> **Last updated:** 2026-03-18
> **Status:** Active

---

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-15 | Initial roadmap — Phase 1 included "custom taint engine" build | — |
| v2 | 2026-03-16 | Phase 1: taint engine → constant propagation + Semgrep rules. Phase 2: added Joern integration. | ADR-004 |
| v3 | 2026-03-17 | Phase 1: added GitHub, GitLab, Bitbucket (Cloud + Data Center) git hosting integrations | A-003 resolution |
| v4 | 2026-03-18 | Phase 1: Semgrep → OpenGrep (Pass 2 engine). Git hosting integrations moved to Phase 2 (require backend server). | ADR-009 |

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
- [ ] tree-sitter integration with language detection and dispatch
- [ ] AST-based detection for **Java, Python, JavaScript/TypeScript** (3 languages)
- [ ] Library API model for: JCA/JCE, Bouncy Castle, `cryptography` (Python), `hashlib`, Node.js `crypto`, `jsonwebtoken`
- [ ] Regex layer: PEM headers, key blobs, algorithm name strings
- [ ] Config file scanner: `.env`, `*.properties`, basic YAML
- [ ] **Pass 1: Constant propagation** — intra-procedural variable tracking + project-wide symbol table *(replaces "custom taint engine" from v1 — see ADR-004)*
- [ ] **Pass 2: OpenGrep taint rules** — initial rule set for Java, Python, JS/TS covering common crypto patterns (OpenGrep replaces Semgrep per ADR-009)
- [ ] Confidence scoring (High / Medium / Low / Unresolved)
- [ ] File/line/column location for every finding

**Detection Coverage (Phase 1)**
- [ ] Algorithms with name, mode, padding, key size
- [ ] Hardcoded key material (constant → key parameter taint)
- [ ] Static IV / nonce (constant → IV parameter taint)
- [ ] Weak PRNG for security use
- [ ] Disabled certificate validation
- [ ] Deprecated TLS version (explicit config)

**Output**
- [ ] CycloneDX 1.7 JSON — full `cryptoProperties` for all asset types
- [ ] SARIF 2.1 output
- [ ] Text summary output to terminal
- [ ] PDF detailed report — per-finding breakdown, quantum status summary, severity distribution (Go: `maroto` library; Python backend uses ReportLab in Phase 2+)

**NIST Quantum Tagging**
- [ ] `nistQuantumSecurityLevel` populated for all detected algorithms
- [ ] `quantumStatus` tag: `quantum-vulnerable`, `quantum-safe`, `quantum-unknown`, `broken`

**Policy Engine (Basic)**
- [ ] YAML policy file parsing
- [ ] Rule evaluation: algorithm family, key size, TLS version
- [ ] `PASS` / `FAIL` / `WARN` exit codes for CI/CD integration
- [ ] `--fail-on CRITICAL` flag

**CI/CD**
- [ ] GitHub Actions `cbom-action` — scan on push/PR; upload CBOM as artifact
- [ ] GitLab CI template

**CLI Commands**
```bash
cbom scan ./path [--output cbom.json] [--format cyclonedx-json|sarif|text|pdf]
cbom scan <git-url> [--branch main]
cbom diff cbom-before.json cbom-after.json
cbom policy check cbom.json --policy policy.cbom.yml
cbom report cbom.json [--output report.pdf] [--format pdf]
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
- [ ] **Go** analyzer (stdlib `crypto/*`, `golang.org/x/crypto`)
- [ ] **C#** analyzer (Roslyn, `System.Security.Cryptography`, BouncyCastle.NET)
- [ ] **Kotlin** analyzer (reusing Java library model + Kotlin extensions)
- [ ] **PHP** analyzer (`openssl_*`, `hash_*`, `password_hash`, `sodium_*`)
- [ ] **Pass 3: Joern integration** — deep inter-procedural analysis for Java, Kotlin, Python, JS, C/C++ *(added in v2 per ADR-004; runs nightly)*

**Detection Expansion**
- [ ] Certificate parsing from embedded PEM files
- [ ] Certificate expiry checking
- [ ] JWT/JOSE `alg` detection and `alg: none` flagging
- [ ] PBKDF2 / bcrypt / scrypt / Argon2 iteration count checking
- [ ] ECB mode detection
- [ ] PKCS1v15 padding flagging

**Quantum Readiness**
- [ ] Quantum Risk Score per repository (0–100)
- [ ] Migration Priority Queue (ranked service list by quantum exposure)
- [ ] PQC Readiness Report (PDF) — % quantum-safe, top migration targets

**Compliance Mapping**
- [ ] NIST SP 800-131A Rev. 3 — Acceptable / Deprecated / Disallowed tagging
- [ ] FIPS 140-3 compliance checks
- [ ] Compliance gap report (PDF)

**CBOM Management**
- [ ] CBOM versioning — every scan stored as an immutable snapshot
- [ ] CBOM diff API — compare two scans
- [ ] CBOM merge — aggregate multiple CBOMs into one

**Git Hosting Integrations** *(moved from Phase 1 — require backend server)*
- [ ] GitHub — OAuth, webhooks, Checks API, PR review comments
- [ ] GitLab — OAuth, webhooks, MR notes API
- [ ] Bitbucket Cloud — OAuth, webhooks, PR comments API
- [ ] Bitbucket Data Center — PAT auth, webhooks, REST API

**REST API + Basic UI**
- [ ] FastAPI backend with OpenAPI 3.1 spec
- [ ] Scan submission, status polling, results retrieval
- [ ] Basic React dashboard: repository list, latest scan summary, finding list

**Success Criteria**
- 7 languages supported
- Compliance gap reports pass review by a GRC practitioner
- API response time < 200ms for CBOM retrieval

---

## Phase 3 — Enterprise (Months 7–9)

**Goal:** Full language coverage, complete compliance engine, portfolio-level dashboard, enterprise integrations.

### Deliverables

**Language Completion**
- [ ] **C/C++** analyzer (OpenSSL, libsodium, mbedTLS — via Joern)
- [ ] **Rust** analyzer (`ring`, `rustls`, `openssl` crate)
- [ ] **Swift** analyzer (CryptoKit, CommonCrypto)
- [ ] **Ruby** analyzer (OpenSSL, BCrypt, Digest)
- [ ] **Dart/Flutter** analyzer (`package:crypto`, `pointycastle`)

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
- [ ] Multi-tenant support with RBAC
- [ ] CBOM signing via Sigstore / cosign
- [ ] Jira integration — auto-create tickets on policy violation
- [ ] Slack / Teams notifications
- [ ] Dependency-Track integration
- [ ] SonarQube plugin (adds CBOM tab to SonarQube)
- [ ] Self-hosted Docker / Kubernetes deployment package

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
