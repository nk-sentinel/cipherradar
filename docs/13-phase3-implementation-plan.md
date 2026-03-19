# Phase 3 — Implementation Plan

> **Document version:** v3
> **Last updated:** 2026-03-20
> **Status:** Draft

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-20 | Initial plan — 4 workstreams, 19 milestones, 17 new skills, 8 new ADRs |
| v2 | 2026-03-20 | Feasibility analysis applied — SonarQube split, ISO/CRA reframed, Dart approach, stabilization prereqs |
| v3 | 2026-03-20 | Week 1-2 complete: A-M1 (12 langs), B-M1 (multi-tenant), C-M1 (portfolio), D-M1 (Helm) |

---

## Pre-Phase 3 Stabilization (must complete before starting)

| # | Issue | Priority | Effort | Status |
|---|---|---|---|---|
| 1 | **Walker skip bug** — replace `.json` blanket-skip with content-based CycloneDX/SARIF detection | BLOCKER | 2h | ✅ Fixed |
| 2 | **PEM false positive noise** — suppress line-level hex/base64 matches inside PEM blocks; skip `.md` files | HIGH | 3h | ✅ Fixed |
| 3 | **Backend test failures** — fix 5 failing tests + migration test errors | HIGH | 2h | ✅ 145 pass |
| 4 | **Frontend test failures** — fix 7 async timing failures with proper `waitFor` | HIGH | 2h | ✅ 31 pass |
| 5 | **`org_id` denormalization** — add `org_id` to projects, scans, findings, cbom_documents for RLS | MEDIUM | 2h | ✅ Migration 002 |
| 6 | **Dart grammar decision** — CGo binding POC or confirm regex-only approach | MEDIUM | 1d | ✅ Regex-only |

## Feasibility Notes (from analysis, applied to plan)

1. **SonarQube:** Split into two deliverables. Phase 3 delivers `cbom scan --format sonarqube-generic` (generic issue export — 1-2 days, covers 80% of value). Full SonarQube plugin with CBOM tab deferred to Phase 4.
2. **ISO 27001 A.8.24:** Reframed from "compliance score (0-100)" to "evidence generation report for A.8.24 audit." Too high-level for algorithmic scoring.
3. **EU Cyber Resilience Act:** Reframed from "compliance score" to "CRA readiness gap report." Harmonized standards not yet published.
4. **50-repo target:** Clarified as Pass 1+2 only. Joern Pass 3 is nightly and not included in the 30-minute target.
5. **Dart scanner:** Start with regex-based scanner (Dart crypto surface is small). Upgrade to tree-sitter when CGo binding is ready. No grammar in `go-tree-sitter`.
6. **D3.js graph:** Must use Canvas rendering (not SVG) for 500+ node target. WebGL via `react-force-graph` excluded per orchestrator rule (no hybrid libraries).
7. **Teams notifications:** Incoming Webhook first (simple POST). OAuth Teams App deferred to Phase 4.
8. **Multi-tenant RLS:** Requires `org_id` denormalization migration before B-M1 can start.

---

## Overview

Phase 3 transforms CipherRadar from a 7-language platform into a full enterprise product: 12 language scanners, complete compliance engine (6 frameworks), portfolio-level dashboard with interactive visualizations, container scanning, SBOM ingestion, enterprise integrations (Jira, Teams, Sigstore, Dependency-Track, SonarQube), multi-tenant RBAC enforcement, and production Kubernetes deployment.

Phase 3 is significantly larger than Phase 2. It uses **four independent workstreams** (up from three) with a new **Workstream D — Infrastructure & Integrations** to handle Kubernetes, Sigstore, SonarQube plugin, and Dependency-Track integration. Each workstream has its own orchestrator and milestone gates. Cross-workstream integration happens at defined milestones only.

```
Workstream A — CLI: 5 New Languages + Container Scanning + Config Expansion   (Go)
Workstream B — Backend: Compliance Engine + SBOM + Notifications + Enterprise  (Python/FastAPI)
Workstream C — Frontend: Full Dashboard + Portfolio + D3 Graph + Kanban        (React 19 + TypeScript)
Workstream D — Infrastructure: Kubernetes/Helm + Sigstore + SonarQube + DepTrack (Mixed)

   A ──────────────────────────────────────────────────────────────────────►
   B ──────────────────────────────────────────────────────────────────────►
   C ──────────────────────────┬───────────────────────────────────────────►
                               │
                        C depends on B-M3
                        (API contracts ready)
   D ──────────────────────────────────┬───────────────────────────────────►
                                       │
                                D depends on B-M2 (auth + API)
                                D depends on A-M2 (12-lang CLI binary)
```

- **Orchestrator** — strictly coordinates. Assigns subagents in dependency order, merges integration points, and runs all quality/security validation skills after each subagent completes. Never writes implementation code.
- **Subagents** — each owns a single concern. Runs its own skills during implementation. Reports back to the orchestrator when done.

All commits are gated through the appropriate `/commit`, `/commit-py`, or `/commit-fe` skill. No code is merged without passing the orchestrator's milestone-close gate.

---

## Model Configuration

All agents use the same model and effort level — no mixing.

| Setting | Value |
|---|---|
| **Model** | Opus 4.6 (1M context) |
| **Effort** | High |
| **Applies to** | All 4 workstream orchestrators + all subagents |

---

## Skills Reference

### Existing Skills (37 from Phase 1 + Phase 2)

**Go CLI (Workstream A):**

| Skill | Category | Applies to Phase 3? | Notes |
|---|---|---|---|
| `/lint` | Quality | Yes | All A milestones |
| `/test-coverage` | Quality | Yes — **needs modification** | Add thresholds for 5 new scanner packages + container scanner |
| `/sec-review` | Security | Yes | All A milestones |
| `/dep-audit` | Security | Yes | All A milestones |
| `/fuzz` | Security | Yes | All new scanner packages |
| `/commit` | Workflow | Yes | Every A commit |
| `/benchmark` | Performance | Yes — **needs modification** | Add 12-language corpus target + parallel 50-repo target |
| `/profile` | Performance | Yes | When benchmarks miss |
| `/build-cross` | Cross-platform | Yes | Every A gate |
| `/new-scanner` | Scaffolding | Yes | A-M1 (5 new languages) |
| `/new-opengrep-rule` | Scaffolding | Yes | A-M1 (5 new rule files) |
| `/new-joern-query` | Scaffolding | Yes | A-M2 (C/C++ Joern queries) |

**Python Backend (Workstream B):**

| Skill | Category | Applies to Phase 3? | Notes |
|---|---|---|---|
| `/lint-py` | Quality | Yes | All B milestones |
| `/test-py` | Quality | Yes — **needs modification** | Add thresholds for compliance, notifications, SBOM, multi-tenant modules |
| `/sec-py` | Security | Yes | All B milestones |
| `/commit-py` | Workflow | Yes | Every B commit |
| `/new-api-route` | Scaffolding | Yes | B-M1 through B-M4 |
| `/db-migrate` | Database | Yes | B-M1 (multi-tenancy schema), B-M2 (compliance tables) |
| `/db-validate` | Database | Yes | All B milestones |
| `/db-seed` | Database | Yes — **needs modification** | Expand to 5 orgs, 20 projects, 2000+ findings, multi-tenant data |
| `/load-test` | Performance | Yes — **needs modification** | Add 50-repo portfolio target + notification throughput |
| `/profile-py` | Performance | Yes | When load-test misses |
| `/webhook-test` | Integration | Yes | B-M3 (Jira, Teams webhooks) |

**React Frontend (Workstream C):**

| Skill | Category | Applies to Phase 3? | Notes |
|---|---|---|---|
| `/lint-fe` | Quality | Yes | All C milestones |
| `/test-fe` | Quality | Yes — **needs modification** | Add thresholds for D3 graph, calendar, kanban components |
| `/sec-fe` | Security | Yes | All C milestones |
| `/commit-fe` | Workflow | Yes | Every C commit |
| `/build-fe` | Quality | Yes — **needs modification** | Raise bundle limit to 750KB gzip (D3.js adds ~150KB) |
| `/new-page-fe` | Scaffolding | Yes | C-M1 through C-M4 |
| `/mock-api-fe` | Integration | Yes | C-M1 through C-M3 |
| `/a11y-fe` | Quality | Yes | C-M2, C-M3, C-M4 |

**Cross-workstream:**

| Skill | Category | Applies to Phase 3? | Notes |
|---|---|---|---|
| `/adr` | Architecture | Yes | 8 new ADRs before Phase 3 starts |
| `/openapi-sync` | Contract | Yes | B-M3, B-M4, C-M3 |
| `/docker-compose` | Infrastructure | Yes — **needs modification** | Add scanner-worker scaling, MinIO, notification services |
| `/docker-build` | Infrastructure | Yes — **needs modification** | Add scanner-worker image + SonarQube plugin image |
| `/e2e-test` | Integration | Yes — **needs modification** | Expand to cover portfolio, compliance, notifications, multi-tenant |
| `/changelog` | Documentation | Yes | Every milestone close |

### Modified Skills (Phase 2 → Phase 3)

| Skill | Change | Reason |
|---|---|---|
| `/test-coverage` | Add thresholds: C/C++ scanner 80%, Rust scanner 80%, Swift scanner 80%, Ruby scanner 80%, Dart scanner 80%, container scanner 75%, config scanner 80% | 5 new languages + container scanning |
| `/benchmark` | Add targets: 12-language corpus < 10 min; 50-repo portfolio < 30 min (parallel workers); container image scan < 2 min per image; single-file scan < 50ms (unchanged) | Phase 3 success criteria |
| `/test-py` | Add thresholds: notifications service 80%, SBOM service 80%, multi-tenant middleware 90%, Jira integration 75%, Teams integration 75% | New backend modules |
| `/test-fe` | Add thresholds: D3 graph components 60% (visual components harder to unit test), calendar/kanban 70% | New complex UI components |
| `/build-fe` | Raise bundle limit from 500KB to 750KB gzip (D3.js adds ~150KB) | D3 dependency |
| `/db-seed` | Expand to: 5 orgs (multi-tenant), 20 projects, 50 scans, 2000+ findings, compliance scores across 6 frameworks, SBOM links, notification preferences | Enterprise-scale test data |
| `/load-test` | Add targets: portfolio dashboard (50 repos) < 2s; compliance trending < 500ms; notification dispatch < 100ms per event; parallel scan queue (10 concurrent) throughput | Enterprise performance |
| `/docker-compose` | Add services: scanner-worker (scale 4), MinIO (CBOM artifacts), notification worker. Add `docker-compose.prod.yml` validation | Full enterprise stack |
| `/docker-build` | Add images: `cipherradar/scanner-worker:dev`, validate scanner-worker includes CLI binary + tools. Size target: scanner-worker < 800MB (includes Joern) | Scanner worker image |
| `/e2e-test` | Add test paths: portfolio dashboard → heat map → drill-down; compliance dashboard → framework → finding; certificate calendar → expiry alert; CBOM diff → side-by-side; RBAC multi-tenant isolation; Jira ticket creation mock | Full Phase 3 feature coverage |

### New Skills (Phase 3) — 17 total

**Workstream A — CLI:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/new-config-rule` | Scaffolding | Scaffold a config file detection rule (nginx, httpd, openssl.cnf, java.security, k8s manifests, Dockerfiles). Creates parser + pattern matcher + test fixture in `cli/internal/scanner/config/` | Read existing config scanner, create rule file with regex/structured patterns, add test fixture | A-M2 |
| `/container-scan-test` | Integration | Validate OCI image scanning end-to-end: pull image → extract layers → scan filesystem → produce CBOM. Tests against known container images with embedded crypto | `docker pull`, `skopeo copy`, extract layers, `cbom scan --container`, validate CBOM output | A-M3 |

**Workstream B — Backend:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/new-compliance-framework` | Scaffolding | Scaffold a compliance framework mapping: YAML rule definition in `scanner/library-models/`, Python evaluation engine in `backend/app/compliance/`, API route, test fixtures. Each framework follows the same pattern as NIST/FIPS from Phase 2 | Read existing compliance service, create framework YAML + evaluator + tests | B-M2 |
| `/notification-test` | Integration | Test notification dispatch across all channels: in-app, email (mock SMTP), Teams (mock webhook), Jira (mock API). Verify correct routing per trigger/recipient/severity rules from `docs/10-communications.md` | Start mock servers, trigger notification events, verify delivery, check deduplication | B-M3, B-M4 |
| `/sbom-test` | Integration | Validate SBOM ingestion and CBOM-SBOM linking: parse CycloneDX/SPDX SBOMs, link components to CBOM crypto findings, verify component-level crypto inventory | Ingest sample SBOM files, query linked findings, validate component graph | B-M2 |
| `/multi-tenant-test` | Security | Verify tenant isolation: RLS enforcement, cross-tenant query prevention, role cascade, group hierarchy scoping. Tests all 7 roles across 3+ orgs with overlapping data | Create multi-org test data, attempt cross-tenant access with each role, verify 403/404 responses, check RLS at SQL level | B-M1, B-M4 |
| `/signing-test` | Security | Verify CBOM signing and verification via cosign: sign a CBOM artifact, verify signature, check Rekor transparency log entry (or mock). Validates the full Sigstore flow | `cosign sign-blob`, `cosign verify-blob`, Rekor log check | B-M4, D-M2 |

**Workstream C — Frontend:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/d3-graph-test` | Quality | Test D3.js force-directed dependency graph rendering: node/edge data binding, zoom/pan, click interactions, performance with 500+ nodes. Uses Playwright for visual regression | Render graph with fixture data, screenshot comparison, interaction test via Playwright | C-M2 |
| `/visual-regression-fe` | Quality | Capture and compare visual snapshots of dashboard pages across themes (Radar, Crystal, Sentinel). Detects unintended layout changes | `npx playwright test --project=visual`, screenshot diff against baseline per theme | C-M3, C-M4 |

**Workstream D — Infrastructure:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/helm-validate` | Infrastructure | Validate Helm chart: lint, template rendering, dry-run install, schema validation. Ensures chart values align with docker-compose config | `helm lint`, `helm template`, `helm install --dry-run`, `kubeval` on rendered manifests | D-M1 |
| `/helm-test` | Integration | Deploy to local k8s (kind/minikube), run health checks, verify all services start, run smoke test | `kind create cluster`, `helm install`, wait for pods, health check all services, `helm test` | D-M1 |
| `/sonarqube-plugin-build` | Quality | Build SonarQube plugin JAR (Gradle), validate plugin descriptor, test against SonarQube dev instance | `cd plugins/sonarqube && gradle build`, `sonar-scanner`, verify CBOM tab appears | D-M3 |
| `/deptrack-test` | Integration | Validate Dependency-Track integration: CBOM upload, vulnerability correlation, API sync. Tests against Dependency-Track dev instance | Start Dependency-Track container, upload CBOM via API, verify imported components, check auto-correlation | D-M3 |
| `/sigstore-verify` | Security | End-to-end Sigstore verification: keyless signing with cosign, Rekor log entry, verification from a fresh environment. Validates the attestation chain | `cosign sign-blob --yes`, `rekor-cli verify`, `cosign verify-blob` from clean context | D-M2 |
| `/scale-test` | Performance | Validate 50-repository portfolio scanning within 30 minutes: spin up parallel Taskiq workers, submit 50 scan jobs, measure wall-clock completion time, resource utilization | Submit 50 scan jobs to API, monitor worker queue, measure completion time, report CPU/memory per worker | D-M4 |
| `/soc2-checklist` | Compliance | Verify SOC 2 Type II controls: audit logging, encryption at rest/transit, access controls, change management, availability monitoring. Checklist-based validation against implemented controls | Review audit log completeness, check TLS config, verify RLS, check backup config, review monitoring setup | D-M4 |

### New Hooks

| Hook | Trigger | Action |
|---|---|---|
| `helm lint` | After any `.yaml` file write/edit in `deploy/helm/` | `helm lint deploy/helm/cipherradar/` |
| `gradle check` | After any `.java`/`.kt` file write/edit in `plugins/sonarqube/` | `cd plugins/sonarqube && gradle check` |

---

## Workstream A — CLI: 5 New Languages + Container Scanning + Config Expansion (Go)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **A-M1** | Agent-CppScanner | — | No | C/C++ scanner: OpenSSL (`EVP_*`, `SSL_*`, `RSA_*`, `AES_*`, `SHA*`, `HMAC`, `PEM_*`), libsodium (`crypto_*`), mbedTLS (`mbedtls_*`). tree-sitter-c + tree-sitter-cpp grammars. Constprop. Extensions `.c`, `.cpp`, `.cc`, `.h`, `.hpp`. Header-aware: detect API calls in headers. Note: Deep Joern CPG analysis deferred to A-M2 (Joern CPG is C/C++ native — maximum value here). | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-RustScanner | — | Yes | Rust scanner: `ring` (digest, aead, agreement, pbkdf2, rand, signature), `rustls` (ClientConfig, ServerConfig, cipher suites, TLS version), `openssl` crate (ssl, crypto, hash, pkey, rsa, ec). tree-sitter-rust grammar. Constprop. Extensions `.rs`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-SwiftScanner | — | Yes | Swift scanner: CryptoKit (AES.GCM, ChaChaPoly, SHA256/384/512, HMAC, P256/P384/P521, Curve25519, SymmetricKey), CommonCrypto (CCCrypt, CCHmac, CC_SHA*, CCKeyDerivationPBKDF), Security framework (SecKey*, SecCertificate*). tree-sitter-swift grammar. Extensions `.swift`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-RubyScanner | — | Yes | Ruby scanner: OpenSSL (`OpenSSL::Cipher`, `OpenSSL::Digest`, `OpenSSL::PKey`, `OpenSSL::SSL`, `OpenSSL::X509`), BCrypt (`BCrypt::Password`), Digest (`Digest::SHA256`, `Digest::MD5`). tree-sitter-ruby grammar. Extensions `.rb`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-DartScanner | — | Yes | Dart/Flutter scanner: `package:crypto` (sha256, sha1, md5, hmac), `pointycastle` (AES, RSA, SHA, HMAC, Fortuna, PBKDF2), `package:encrypt` (Encrypter, AES). tree-sitter-dart grammar. Extensions `.dart`. | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-OpenGrepRules-Phase3 | — | Yes | OpenGrep rules for C/C++, Rust, Swift, Ruby, Dart. Min 3 rules/language: hardcoded key, static IV, weak PRNG. Add to `scanner/rules/`. | `/new-opengrep-rule`, `/lint` |
| **A-M1** | **Orchestrator gate** | All A-M1 | — | Merge scanner registry (12 languages), merge rules, validate full CLI build | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **A-M2** | Agent-JoernCpp | A-M1 | No | Joern CPG queries for C/C++ — inter-procedural OpenSSL/libsodium analysis. Joern is native to C/C++ CPGs — highest value of any language for Pass 3. Min 5 query scripts: key flow, IV reuse, deprecated API chains, buffer-based key derivation, certificate validation bypass. | `/new-joern-query`, `/lint`, `/test-coverage` |
| **A-M2** | Agent-ConfigExpansion | A-M1 | Yes | Config file parsers: nginx.conf (ssl_protocols, ssl_ciphers, ssl_certificate), httpd.conf (SSLProtocol, SSLCipherSuite), openssl.cnf (default_md, default_bits, oid_section), java.security (jdk.tls.disabledAlgorithms, jdk.certpath.disabledAlgorithms), k8s manifests (TLS secrets, ingress TLS config), Dockerfiles (EXPOSE 443, apt install openssl). Structured parsing (not regex) where possible. | `/new-config-rule`, `/lint`, `/test-coverage` |
| **A-M2** | **Orchestrator gate** | All A-M2 | — | 12 languages + Joern C/C++ + expanded config scanning verified | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **A-M3** | Agent-ContainerScanning | A-M2 | No | OCI image layer scanning: accept image reference or tar, use `go-containerregistry` (crane/gcrane) to extract filesystem layers, scan extracted files with existing 12-language scanner pipeline, merge findings per layer (attribute findings to layer SHA), produce CBOM with container metadata. `cbom scan --container <image:tag>` command. Support local tar and remote registry. | `/lint`, `/sec-review`, `/test-coverage`, `/container-scan-test` |
| **A-M3** | **Orchestrator gate** | A-M3 | — | Full Workstream A close: 12 languages, container scanning, config expansion, Joern C/C++ | `/lint`, `/sec-review`, `/dep-audit`, `/test-coverage`, `/fuzz`, `/benchmark`, `/build-cross`, `/container-scan-test` |

---

## Workstream B — Backend: Compliance Engine + SBOM + Notifications + Enterprise (Python/FastAPI)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **B-M1** | Agent-MultiTenantRBAC | — | No | Full multi-tenant enforcement: PostgreSQL RLS policies per org_id on all tables. Group hierarchy with unlimited nesting (materialized path or closure table). Role assignment at org/group/project level with cascade. All 7 roles enforced at the API layer (middleware). Tenant context injection via JWT claims. Group-scoped queries for Team Manager role. Test with 3+ orgs to verify isolation. | `/db-migrate`, `/lint-py`, `/sec-py`, `/test-py`, `/multi-tenant-test` |
| **B-M1** | **Orchestrator gate** | B-M1 | — | Multi-tenant RLS verified, cross-tenant queries blocked, 7-role enforcement tested | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/multi-tenant-test` |
| **B-M2** | Agent-CompliancePCIDSS | B-M1 | No | PCI-DSS v4.0 compliance mapping: map crypto findings to PCI-DSS requirements (Req 2.2.7 — strong crypto for non-console admin, Req 3.5 — key management, Req 4.2 — strong crypto for transmission, Req 6.2.4 — secure coding). Score 0-100 per repository. YAML rules in `scanner/library-models/pci_dss_v4.yml`. | `/new-compliance-framework`, `/lint-py`, `/test-py` |
| **B-M2** | Agent-ComplianceCNSA | B-M1 | Yes | NSA CNSA 2.0 compliance mapping + timeline tracker: map algorithms to CNSA 2.0 approved list (AES-256, SHA-384+, ML-KEM, ML-DSA, SLH-DSA). Timeline: 2025 exclusivity deadline, 2030 NSS requirement. Track per-finding migration deadline. YAML rules in `scanner/library-models/cnsa_2.yml`. | `/new-compliance-framework`, `/lint-py`, `/test-py` |
| **B-M2** | Agent-ComplianceISO | B-M1 | Yes | ISO 27001:2022 A.8.24 mapping: Annex A control 8.24 — "Use of cryptography" evaluation. Map findings to control objectives: key management lifecycle, algorithm appropriateness, protocol compliance. Score 0-100. YAML rules in `scanner/library-models/iso_27001_a8_24.yml`. | `/new-compliance-framework`, `/lint-py`, `/test-py` |
| **B-M2** | Agent-ComplianceCRA | B-M1 | Yes | EU Cyber Resilience Act gap report: map findings against CRA Annex I essential requirements (state-of-the-art crypto, secure defaults, updatable crypto, vulnerability disclosure). Gap report format for CRA compliance evidence. YAML rules in `scanner/library-models/eu_cra.yml`. | `/new-compliance-framework`, `/lint-py`, `/test-py` |
| **B-M2** | Agent-ComplianceTrending | Agent-CompliancePCIDSS | No | Compliance score trending over time: TimescaleDB hypertable for compliance_scores (org_id, project_id, framework, score, timestamp). Continuous aggregate for daily/weekly/monthly roll-ups. API endpoints: `GET /api/v1/compliance/trends?framework=pci-dss&period=30d`. | `/db-migrate`, `/lint-py`, `/test-py` |
| **B-M2** | Agent-SBOMIngestion | B-M1 | Yes | SBOM ingestion + CBOM-SBOM linking: accept CycloneDX and SPDX SBOM uploads. Parse SBOM components (library name, version, purl). Link SBOM components to CBOM crypto findings (library X uses algorithm Y). API: `POST /api/v1/sbom/upload`, `GET /api/v1/projects/{id}/sbom-cbom-link`. Store SBOM via same CBOMStore pattern. | `/new-api-route`, `/lint-py`, `/test-py`, `/sbom-test` |
| **B-M2** | **Orchestrator gate** | All B-M2 | — | 6 compliance frameworks (NIST + FIPS + 4 new), trending, SBOM ingestion verified | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/db-seed` |
| **B-M3** | Agent-NotificationEngine | B-M2 | No | Notification dispatch engine: all 17 triggers from `docs/10-communications.md`. Channels: in-app (WebSocket push), email (SMTP with Jinja2 templates — immediate + digest modes), Microsoft Teams (Adaptive Cards via webhook or OAuth app). Routing per recipient type/role/severity. Configuration cascade (org → group → user preferences). Deduplication. Notification model in DB. WebSocket endpoint for real-time in-app delivery. | `/new-api-route`, `/lint-py`, `/test-py`, `/notification-test` |
| **B-M3** | Agent-JiraIntegration | B-M2 | Yes | Jira integration: OAuth 2.0 connection flow. Auto-create tickets on triggers T-02, T-03, T-05, T-07, T-08, T-11 (per `docs/10-communications.md`). Deduplication (check existing open ticket for same finding ID). Pre-filled fields: summary, description (Jira markup format from comms spec), severity, CWE, labels. Project mapping (CipherRadar project → Jira project key). One-way sync (Phase 3). API: `POST /api/v1/integrations/jira/connect`, `GET /api/v1/integrations/jira/status`. | `/new-api-route`, `/lint-py`, `/test-py`, `/notification-test` |
| **B-M3** | Agent-CBOMSigning | B-M2 | Yes | CBOM signing via Sigstore/cosign: sign CBOM artifacts at scan completion. Store signature + Rekor log entry ID alongside CBOM. Verification endpoint: `GET /api/v1/cbom/{id}/verify`. Signed CBOMs visible to Compliance Auditor and Guest/Viewer roles (unsigned hidden per RBAC spec). Integration with cosign Go library or subprocess. | `/lint-py`, `/sec-py`, `/test-py`, `/signing-test` |
| **B-M3** | **Orchestrator gate** | All B-M3 | — | Notifications dispatch across all channels, Jira ticket creation, CBOM signing verified. OpenAPI spec frozen for frontend. | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/notification-test`, `/signing-test`, `/openapi-sync` |
| **B-M4** | Agent-PortfolioAPI | B-M3 | No | Portfolio-level API endpoints: `GET /api/v1/portfolio/summary` (all repos, heat map data, quantum readiness %), `GET /api/v1/portfolio/compliance` (per-framework scores across all repos), `GET /api/v1/portfolio/quantum` (aggregate quantum readiness). Group-scoped for Team Manager role. Redis caching for portfolio aggregations (invalidate on new scan completion). | `/new-api-route`, `/lint-py`, `/test-py` |
| **B-M4** | Agent-BackendPerformance-P3 | B-M3 | Yes | Performance validation: 50-repo portfolio query < 2s, compliance trending < 500ms, notification dispatch < 100ms/event, parallel scan queue (10 concurrent workers). Redis caching for portfolio aggregations. Connection pooling tuning. Query optimization for cross-repo aggregations. | `/lint-py`, `/test-py`, `/load-test`, `/profile-py`, `/db-seed` |
| **B-M4** | **Orchestrator gate** | All B-M4 | — | Full Workstream B close: 6 frameworks, SBOM, notifications, Jira, signing, portfolio API, perf targets | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/load-test`, `/docker-build`, `/openapi-sync`, `/multi-tenant-test` |

---

## Workstream C — Frontend: Full Dashboard (React 19 + TypeScript)

**UI Reference:** `frontend/mockups/full-mockup-v2.html` remains the accepted mockup. Phase 3 frontend agents MUST reference this mockup for all new pages.

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **C-M1** | Agent-PortfolioDashboard | — | No | Portfolio dashboard page: org-wide heat map (repos × severity), quantum readiness % gauge, total finding distribution chart, top-10 riskiest repos table. Group-scoped view for Team Manager. TanStack Query for data fetching. Recharts for heat map + charts. Mock API. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/mock-api-fe` |
| **C-M1** | Agent-AssetExplorer | — | Yes | Asset explorer page: searchable, filterable crypto inventory table. Columns: asset name, type (algorithm/protocol/key/certificate), language, repository, file:line, quantum status, compliance status. Full-text search. Faceted filters (type, language, quantum status, compliance framework). Pagination. Export to CSV. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/mock-api-fe` |
| **C-M1** | **Orchestrator gate** | All C-M1 | — | Portfolio + asset explorer render, filters work, mock API serves data | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/mock-api-fe` |
| **C-M2** | Agent-DependencyGraph | C-M1 | No | Interactive D3.js force-directed dependency graph: nodes = crypto assets (sized by severity), edges = dependency relationships (library → algorithm → protocol), zoom/pan, click to drill down to finding detail, filter by language/quantum status. Performance target: smooth at 500+ nodes. Separate D3 rendering layer from React lifecycle (useRef + useEffect pattern). | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/d3-graph-test` |
| **C-M2** | Agent-CertCalendar | C-M1 | Yes | Certificate expiry calendar: monthly calendar view showing cert expiry dates. Color-coded by urgency (green > 90d, yellow 30-90d, orange 7-30d, red < 7d / expired). Click date to see cert details. List view alternative. Integration with notification triggers T-06/T-07/T-08. | `/new-page-fe`, `/lint-fe`, `/test-fe` |
| **C-M2** | Agent-ComplianceDashboard | C-M1 | Yes | Compliance dashboard: per-framework score cards (NIST, FIPS, PCI-DSS, CNSA 2.0, ISO 27001, CRA). Trend sparkline per framework. Drill-down: click framework → finding list filtered by that framework's violations. CNSA 2.0 timeline tracker view. Compliance score comparison across repos (bar chart). | `/new-page-fe`, `/lint-fe`, `/test-fe` |
| **C-M2** | Agent-CBOMDiffView | C-M1 | Yes | CBOM diff view: side-by-side snapshot comparison. Select two scans (date picker or scan selector). Show added/removed/changed findings with syntax-highlighted diff. Summary: + N new findings, - M resolved, ~ K changed. Filter diff by severity/type. | `/new-page-fe`, `/lint-fe`, `/test-fe` |
| **C-M2** | **Orchestrator gate** | All C-M2 | — | All pages render, D3 graph performs at 500+ nodes, filters/interactions work | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/a11y-fe`, `/d3-graph-test` |
| **C-M3** | Agent-MigrationKanban | C-M2 | No | Migration Kanban board: columns = To Do / In Progress / In Review / Done. Cards = migration tasks (one per quantum-vulnerable finding or algorithm migration). Drag-and-drop between columns. Card detail: finding link, recommended replacement, priority, assignee, deadline (from CNSA 2.0 timeline). Bulk actions. Filter by repo/language/framework. | `/new-page-fe`, `/lint-fe`, `/test-fe` |
| **C-M3** | Agent-NotificationUI | C-M2 | Yes | Notification center: bell icon with unread count badge. Dropdown with notification list (severity dot, message, timestamp, link). Mark all as read. Notification preferences page: per-trigger subscribe/unsubscribe, cadence (immediate/digest), snooze per project. WebSocket connection for real-time push. Integration settings page: Jira connection status, Teams webhook config. | `/new-page-fe`, `/lint-fe`, `/test-fe` |
| **C-M3** | Agent-FrontendAPIIntegration-P3 | C-M2 + **B-M3** | No | Replace mock API with live backend for all new Phase 3 pages. Regenerate TS types from frozen OpenAPI spec. Verify portfolio, compliance trending, asset explorer, dependency graph, certificate calendar, CBOM diff, kanban, and notification endpoints work against live data. CORS config for new endpoints. | `/lint-fe`, `/test-fe`, `/openapi-sync`, `/mock-api-fe` |
| **C-M3** | **Orchestrator gate** | All C-M3 | — | All Phase 3 pages against live backend | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/a11y-fe`, `/openapi-sync` |
| **C-M4** | Agent-MultiTenantFrontend | C-M3 | No | Multi-tenant UI enforcement: sidebar nav visibility per role (7 roles). Group-scoped views for Team Manager. Org switcher for users in multiple orgs. Admin settings pages: org config, user management, integration management, audit log viewer. All admin pages behind Org Admin / Security Manager RBAC guards. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/a11y-fe` |
| **C-M4** | Agent-VisualPolish | C-M3 | Yes | Visual regression baseline + theme verification: all 3 themes (Radar, Crystal, Sentinel) render correctly on all new pages. Screenshot baseline for visual regression. Bundle optimization (code-split D3 graph). | `/lint-fe`, `/test-fe`, `/build-fe`, `/visual-regression-fe` |
| **C-M4** | **Orchestrator gate** | All C-M4 | — | Full Workstream C close: all pages, all themes, multi-tenant UI, production build clean | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/a11y-fe`, `/visual-regression-fe`, `/docker-build`, `/openapi-sync` |

---

## Workstream D — Infrastructure & Integrations (Mixed)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **D-M1** | Agent-HelmChart | — | No | Kubernetes Helm chart: `deploy/helm/cipherradar/`. Chart includes: API deployment + service + ingress, frontend deployment + service + ingress, scanner-worker deployment (configurable replicas), PostgreSQL (TimescaleDB) StatefulSet or external DB config, Redis deployment, MinIO deployment or external S3 config, notification worker. Values.yaml with environment-specific overrides. ConfigMaps for non-secret config. Secrets for JWT key, DB password, API keys. Health/readiness probes. Resource limits. PodDisruptionBudgets. HPA for scanner-worker. | `/helm-validate`, `/helm-test` |
| **D-M1** | Agent-K8sManifests | — | Yes | Raw Kubernetes manifests in `deploy/k8s/` as alternative to Helm: namespace, deployments, services, ingress, configmaps, secrets, HPA, PDB. For teams that do not use Helm. Kustomize overlays for dev/staging/prod. | `/lint` |
| **D-M1** | **Orchestrator gate** | All D-M1 | — | Helm chart lints, templates render, dry-run install succeeds, kind cluster deployment verified | `/helm-validate`, `/helm-test` |
| **D-M2** | Agent-SigstoreIntegration | D-M1 + **B-M3** | No | Sigstore infrastructure: cosign installation in scanner-worker image, keyless signing configuration (Fulcio + Rekor), CBOM attestation workflow (sign on scan completion), verification endpoint integration with backend, Rekor transparency log entry storage. Documentation for self-hosted Sigstore (enterprise air-gapped). | `/sigstore-verify`, `/signing-test`, `/docker-build` |
| **D-M2** | **Orchestrator gate** | D-M2 | — | CBOM signing works in k8s deployment, verification passes from external client | `/sigstore-verify`, `/signing-test` |
| **D-M3** | Agent-SonarQubePlugin | D-M2 + **A-M2** | No | SonarQube plugin (Java/Kotlin, Gradle build): `plugins/sonarqube/`. Adds a "CBOM" tab to SonarQube project dashboard. Plugin calls CipherRadar API to fetch latest CBOM for the project. Displays finding summary, quantum readiness %, compliance scores. SonarQube Marketplace metadata. Plugin descriptor. Integration tests against SonarQube dev instance. | `/sonarqube-plugin-build`, `/lint` |
| **D-M3** | Agent-DepTrackIntegration | D-M2 + **B-M3** | Yes | Dependency-Track integration: CBOM export in Dependency-Track compatible format, automatic upload on scan completion, vulnerability correlation (Dependency-Track VulnDB + CipherRadar crypto findings). API config: `POST /api/v1/integrations/dependency-track/connect`. Bidirectional: DT vulnerability data enriches CBOM findings. | `/deptrack-test`, `/lint-py`, `/test-py` |
| **D-M3** | **Orchestrator gate** | All D-M3 | — | SonarQube plugin builds + displays CBOM tab, Dependency-Track integration verified | `/sonarqube-plugin-build`, `/deptrack-test` |
| **D-M4** | Agent-ScaleValidation | D-M3 + **B-M4** | No | Scale validation: 50-repository portfolio scan within 30 minutes. Spawn parallel Taskiq workers (configurable 4-16). Monitor queue depth, worker utilization, memory pressure. Horizontal pod autoscaler verification in k8s. Report: wall-clock time, per-repo scan time, queue wait time, resource utilization. | `/scale-test`, `/load-test`, `/benchmark` |
| **D-M4** | Agent-SOC2Controls | D-M3 | Yes | SOC 2 Type II control implementation: audit logging (all CRUD, auth events, scan events, policy changes — immutable TimescaleDB hypertable), encryption at rest (PostgreSQL TDE or application-level), encryption in transit (TLS 1.3 on all internal service communication), access controls (RLS + RBAC verified), change management (git-based, immutable CBOM snapshots), availability monitoring (health endpoints, Prometheus metrics, alerting rules). | `/soc2-checklist`, `/lint-py`, `/sec-py` |
| **D-M4** | **Orchestrator gate** | All D-M4 | — | Full Workstream D close: Helm deploys, Sigstore signs, SonarQube + DepTrack integrate, 50-repo scale target met, SOC 2 controls verified | `/helm-validate`, `/helm-test`, `/scale-test`, `/soc2-checklist`, `/docker-build` |

---

## Cross-Workstream Dependencies

```
A-M1 ─────► A-M2 ─────► A-M3                    (sequential within A)
B-M1 ─────► B-M2 ─────► B-M3 ─────► B-M4        (sequential within B)
C-M1 ─────► C-M2 ─────► C-M3 ─────► C-M4        (sequential within C)
D-M1 ─────► D-M2 ─────► D-M3 ─────► D-M4        (sequential within D)
                          │     │
              C-M3 ◄──────┘     │    (C-M3 depends on B-M3 API freeze)
              D-M2 ◄────────────┘    (D-M2 depends on B-M3 signing API)
              D-M3 ◄── A-M2 + B-M3  (SonarQube needs 12-lang CLI; DepTrack needs API)
              D-M4 ◄── B-M4          (Scale test needs portfolio API)
```

| Dependency | From | To | What |
|---|---|---|---|
| API contract freeze | B-M3 | C-M3 | Frontend integrates with live backend. B-M3 gate freezes OpenAPI spec. |
| CBOM signing API | B-M3 | D-M2 | Sigstore infrastructure needs backend signing endpoint. |
| 12-language CLI binary | A-M2 | D-M3 | SonarQube plugin and scanner-worker image need full 12-language CLI. |
| Compliance + notification APIs | B-M3 | D-M3 | Dependency-Track integration uses compliance and notification APIs. |
| Portfolio API | B-M4 | D-M4 | Scale test validates portfolio-level query performance. |
| Shared assets | `scanner/library-models/` | A + B | CLI embeds via `//go:embed`, backend via `importlib.resources`. Phase 3 adds 4 new compliance framework YAMLs. |
| Multi-tenant middleware | B-M1 | C-M4 | Frontend multi-tenant UI requires backend RLS + group hierarchy. |

---

## New ADRs Required

| ADR | Title | Workstream | Timing | Key Decision |
|---|---|---|---|---|
| ADR-016 | Container Image Scanning Architecture — OCI layer extraction vs. mounted filesystem | A | Before A-M3 | go-containerregistry for layer extraction; scan per layer; attribute findings to layer SHA |
| ADR-017 | Multi-Tenant Data Isolation — RLS vs. schema-per-tenant vs. DB-per-tenant | B | Before B-M1 | RLS with org_id on all tables; materialized path for group hierarchy |
| ADR-018 | SBOM Ingestion and CBOM-SBOM Linking Model | B | Before B-M2 | Accept CycloneDX + SPDX; link via purl matching; store SBOM via CBOMStore |
| ADR-019 | Notification Architecture — event bus vs. direct dispatch vs. outbox pattern | B | Before B-M3 | Transactional outbox pattern with Taskiq workers; prevents notification loss on crash |
| ADR-020 | CBOM Signing Strategy — Sigstore keyless vs. org-managed keys | D | Before D-M2 | Keyless (Fulcio + Rekor) for SaaS; org-managed keys option for air-gapped enterprise |
| ADR-021 | SonarQube Plugin Architecture — embedded scanner vs. API client | D | Before D-M3 | API client (thin plugin); plugin calls CipherRadar API, does not embed scanner |
| ADR-022 | Kubernetes Deployment Model — Helm-only vs. Helm + Kustomize | D | Before D-M1 | Helm primary, raw manifests + Kustomize as alternative for non-Helm shops |
| ADR-023 | Compliance Framework Extensibility — plugin model vs. YAML-driven | B | Before B-M2 | YAML-driven rules in `scanner/library-models/`; no plugin system in Phase 3 |

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
7. New scanners follow Phase 1/2 patterns exactly (same interface, constprop, fuzz template).
8. C/C++ scanner must handle header files (`.h`, `.hpp`) — API calls often appear in headers.
9. Container scanning is additive — reuses existing scanner pipeline on extracted filesystem.

### Workstream B

10. OpenAPI spec frozen at B-M3 before C-M3 and D-M3 begin.
11. Never store CBOM JSON as a Postgres column (use CBOMStore abstraction).
12. Never bypass the Graph Abstraction Layer.
13. Shared assets embedded via `importlib.resources`, never loaded from filesystem at runtime.
14. Multi-tenant RLS must be verified with cross-tenant access tests at every B milestone.
15. Notification dispatch must be idempotent — duplicate events must not create duplicate notifications.

### Workstream C

16. Strict TypeScript — `strict: true`, no `any` except generated code.
17. Functional components only — no class components.
18. TanStack Query for all server state — no `useState` + `useEffect` fetch patterns.
19. Mock API for C-M1 and C-M2 — real API integration only at C-M3.
20. D3.js graph rendering decoupled from React lifecycle (useRef + useEffect pattern, no D3-React hybrid libraries).
21. All new pages must work in all 3 themes (Radar, Crystal, Sentinel).

### Workstream D

22. Helm chart must pass `helm lint` and `helm template` before any commit.
23. SonarQube plugin is a thin API client — no scanner logic in the plugin.
24. All k8s deployments must specify resource limits, health probes, and non-root security context.
25. Sigstore verification must work from a completely fresh environment (no pre-shared keys).

---

## Success Criteria Mapped to Gates

| Criterion | Gate | Workstream |
|---|---|---|
| 12 languages supported | A-M1 gate | A |
| C/C++ Joern deep analysis | A-M2 gate | A |
| Container image scanning | A-M3 gate | A |
| Config file expansion (nginx, httpd, openssl.cnf, java.security, k8s, Docker) | A-M2 gate | A |
| PCI-DSS v4.0 compliance mapping | B-M2 gate | B |
| NSA CNSA 2.0 compliance mapping + timeline | B-M2 gate | B |
| ISO 27001:2022 A.8.24 mapping | B-M2 gate | B |
| EU Cyber Resilience Act gap report | B-M2 gate | B |
| Compliance score trending over time | B-M2 gate | B |
| SBOM ingestion + CBOM-SBOM linking | B-M2 gate | B |
| Multi-tenant RBAC (7 roles, group scoping) | B-M1 gate + B-M4 gate | B |
| CBOM signing via Sigstore/cosign | B-M3 gate + D-M2 gate | B + D |
| Jira integration (auto-create tickets) | B-M3 gate | B |
| Teams notifications (Adaptive Cards) | B-M3 gate | B |
| Portfolio dashboard (heat map, quantum %) | C-M1 gate | C |
| Asset explorer (searchable, filterable) | C-M1 gate | C |
| Dependency graph (D3 force-directed) | C-M2 gate | C |
| Certificate expiry calendar | C-M2 gate | C |
| Compliance dashboard (per-framework drill-down) | C-M2 gate | C |
| CBOM diff view (side-by-side) | C-M2 gate | C |
| Migration Kanban board | C-M3 gate | C |
| Dependency-Track integration | D-M3 gate | D |
| SonarQube plugin | D-M3 gate | D |
| Kubernetes/Helm deployment package | D-M1 gate | D |
| Portfolio of 50 repos scannable within 30 min | D-M4 gate | D |
| SOC 2 Type II compliance | D-M4 gate | D |
| No HIGH/CRITICAL security findings | Every gate | All |
| FP rate < 10% for High/Critical (new langs) | A-M1 gate | A |
| All platforms build (CLI) | Every A gate | A |

---

## Milestone Sequencing

```
Week 1-2:    A-M1 + B-M1 + C-M1 + D-M1        (all start in parallel)
Week 3-4:    A-M2 + B-M2 + C-M2                 (D-M1 may still be in progress)
Week 5-6:    A-M3 + B-M3 + C-M2 (cont.) + D-M2 (after B-M3 starts)
Week 7-8:           B-M3 (cont.) + C-M3 + D-M2  (C-M3 waits for B-M3 API freeze)
Week 9-10:          B-M4 + C-M3 (cont.) + D-M3  (D-M3 needs A-M2 + B-M3)
Week 11-12:         C-M4 + D-M4                  (D-M4 needs B-M4)
Week 13:     Final integration                    (full stack verification)
```

### Week-by-Week Detail

| Week | Workstream A | Workstream B | Workstream C | Workstream D |
|---|---|---|---|---|
| 1 | A-M1: 5 scanners (parallel agents) | B-M1: Multi-tenant RBAC | C-M1: Portfolio + asset explorer | D-M1: Helm chart + k8s manifests |
| 2 | A-M1: OpenGrep rules, gate | B-M1: RLS + 7-role enforcement, gate | C-M1: gate | D-M1: kind cluster test, gate |
| 3 | A-M2: Joern C/C++ + config expansion | B-M2: 4 compliance frameworks (parallel) | C-M2: D3 graph + cert calendar | — |
| 4 | A-M2: gate | B-M2: trending + SBOM, gate | C-M2: compliance dashboard + diff view | — |
| 5 | A-M3: Container scanning | B-M3: Notification engine | C-M2: gate | D-M2: Sigstore infra |
| 6 | A-M3: gate | B-M3: Jira + CBOM signing | — | D-M2: gate |
| 7 | — | B-M3: gate (API freeze) | C-M3: Kanban + notifications UI | D-M3: SonarQube plugin |
| 8 | — | B-M4: Portfolio API | C-M3: API integration, gate | D-M3: DepTrack integration |
| 9 | — | B-M4: Performance, gate | C-M4: Multi-tenant UI | D-M3: gate |
| 10 | — | — | C-M4: Visual polish | D-M4: Scale validation |
| 11 | — | — | C-M4: gate | D-M4: SOC 2 controls |
| 12 | — | — | — | D-M4: gate |
| 13 | Final integration: Docker Compose + Helm full stack, E2E tests, changelog | | | |

### Final Integration (Week 13)

Skills: `/docker-compose`, `/docker-build`, `/helm-validate`, `/helm-test`, `/e2e-test`, `/scale-test`, `/changelog`

Validation:
1. `docker compose up` starts all services (API, frontend, scanner-worker x4, PostgreSQL, Redis, MinIO, notification worker)
2. `helm install` to kind cluster starts all pods, passes health checks
3. `/e2e-test` — Playwright: submit scan → poll → CBOM in dashboard → portfolio view → compliance drill-down → D3 graph → certificate calendar → CBOM diff → kanban → notification bell → Jira ticket mock → RBAC multi-tenant isolation
4. `/scale-test` — 50 repos submitted, all complete within 30 min
5. `/docker-build` — verify all image sizes, non-root, distroless
6. `/soc2-checklist` — all SOC 2 controls verified
7. `/changelog` — generate release notes for Phase 3

Estimated duration: 13 weeks (Months 7-9 per roadmap, with 1-week buffer).
```

---
