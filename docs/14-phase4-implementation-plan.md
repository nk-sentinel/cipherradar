# Phase 4 -- Implementation Plan

> **Document version:** v2
> **Last updated:** 2026-03-22
> **Status:** Complete

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-22 | Initial plan -- 3 workstreams, 21 milestones, 14 new skills, 7 new ADRs |
| v2 | 2026-03-22 | Phase 4 complete -- all milestones delivered, all stabilization items resolved, ADR-026 through ADR-032 accepted |

---

## Pre-Phase 4 Stabilization (must complete before starting)

| # | Issue | Priority | Effort | Status |
|---|---|---|---|---|
| 1 | **Binary scanning ADR** -- decide byte-pattern scanning architecture before A-M1 | BLOCKER | 1d | Complete |
| 2 | **LLM provider abstraction** -- select provider model (OpenAI/Anthropic/self-hosted) before B-M2 | BLOCKER | 4h | Complete |
| 3 | **VS Code extension packaging** -- verify `vsce` toolchain, establish extension repo structure under monorepo (`extensions/vscode/`) | HIGH | 4h | Complete |
| 4 | **IntelliJ plugin Gradle setup** -- verify IntelliJ Platform Plugin SDK compatibility, establish `plugins/intellij/` project | HIGH | 4h | Complete |
| 5 | **OpenTelemetry receiver spike** -- confirm OTel collector custom receiver approach vs. standalone gRPC service | HIGH | 1d | Complete |
| 6 | **SonarQube plugin port** -- Phase 3 deferred D-M3 SonarQube full plugin; verify `plugins/sonarqube/` skeleton state | MEDIUM | 2h | Complete |
| 7 | **Phase 3 regression suite** -- run full E2E + benchmark + scale test to confirm baseline before extending | HIGH | 2h | Complete |

## Feasibility Notes

1. **Binary scanning:** JAR/wheel/ELF byte-pattern scanning for crypto constants (AES S-box, known algorithm OIDs, key schedule constants) is well-established in tools like `crypto-detector` (Carnegie Mellon) and `findcrypt-yara`. Approach: YARA rules for known crypto constants embedded via `//go:embed`. Does not require disassembly -- pure byte-pattern matching.
2. **LLM remediation:** Must support multiple LLM providers with a common interface. Never auto-apply -- always "suggested." Context window must include: finding, surrounding code (50 lines), library imports, project language. Target: < 5s per remediation generation.
3. **VS Code extension:** TypeScript + VS Code Extension API. Communicates with the CipherRadar backend API or reads CBOM JSON from local scan output. Language Server Protocol (LSP) not needed -- diagnostics API is sufficient for inline findings.
4. **IntelliJ plugin:** Kotlin + IntelliJ Platform Plugin SDK. External annotator API for line-level annotations. Communicates via same backend API or local CBOM.
5. **OpenTelemetry receiver:** Custom OTel collector receiver plugin (Go) that accepts spans with crypto-annotated attributes. Alternative: standalone gRPC/HTTP receiver that speaks OTLP. Collector plugin preferred for ecosystem compatibility.
6. **Pre-commit hook:** Lightweight -- pure regex scan only (no tree-sitter, no AST). Targets: PEM private keys, hardcoded hex keys > 128 bits, API key patterns. Must complete in < 2s on 100 changed files.
7. **HNDL risk model:** "Harvest Now, Decrypt Later" is a time-based risk function: `HNDL_risk = f(data_sensitivity, encryption_strength, expected_quantum_timeline)`. Requires data classification metadata (user-annotated or inferred). Score per-finding + aggregate per-service.
8. **Cryptographic Agility Score:** Measures how easily a service can migrate its crypto. Factors: number of distinct crypto call sites, library abstraction level (direct API vs. wrapper), algorithm diversity, configuration externalization. Score 0-100 per service.

---

## Overview

Phase 4 differentiates CipherRadar from every other tool in the market. It adds developer-facing IDE integrations (VS Code + IntelliJ), advances detection into binary/compiled artifacts, introduces LLM-assisted remediation, enriches static CBOMs with runtime data via OpenTelemetry, and delivers the full SonarQube plugin deferred from Phase 3.

Phase 4 uses **three workstreams** (reduced from four -- infrastructure work is folded into Workstream B since the Helm/K8s foundation from Phase 3 is stable):

```
Workstream A -- CLI: Binary Scanning + Pre-commit Hook + Custom Source/Sink Config   (Go)
Workstream B -- Backend + IDE: LLM Remediation + Runtime Enrichment (OTel) + SonarQube + VS Code + IntelliJ   (Python/FastAPI + TypeScript + Kotlin)
Workstream C -- Frontend: Remediation Preview + Runtime View + Agility Score + HNDL Risk Model   (React 19 + TypeScript)

   A ──────────────────────────────────────────────────────────────────────►
   B ──────────────────────────────────────────────────┬───────────────────►
                                                       │
                                          B-M5 (IDE) depends on B-M2 (LLM API)
                                          B-M4 (OTel view) needs B-M3 (OTel receiver)
   C ───────────────────────────┬──────────────────────────────────────────►
                                │
                          C depends on B-M2 (LLM API) + B-M3 (OTel API)
```

- **Orchestrator** -- strictly coordinates. Assigns subagents in dependency order, merges integration points, and runs all quality/security validation skills after each subagent completes. Never writes implementation code.
- **Subagents** -- each owns a single concern. Runs its own skills during implementation. Reports back to the orchestrator when done.

All commits are gated through the appropriate `/commit`, `/commit-py`, or `/commit-fe` skill. No code is merged without passing the orchestrator's milestone-close gate.

---

## Model Configuration

All agents use the same model and effort level -- no mixing.

| Setting | Value |
|---|---|
| **Model** | Opus 4.6 (1M context) |
| **Effort** | High |
| **Applies to** | All 3 workstream orchestrators + all subagents |

---

## Skills Reference

### Existing Skills (70 files, 37 project-specific + 33 generic)

**Go CLI (Workstream A):**

| Skill | Category | Applies to Phase 4? | Notes |
|---|---|---|---|
| `/lint` | Quality | Yes | All A milestones |
| `/test-coverage` | Quality | Yes -- **needs modification** | Add thresholds for binary scanner, pre-commit hook, source/sink config |
| `/sec-review` | Security | Yes | All A milestones |
| `/dep-audit` | Security | Yes | All A milestones |
| `/fuzz` | Security | Yes | Binary scanner + source/sink config parser |
| `/commit` | Workflow | Yes | Every A commit |
| `/benchmark` | Performance | Yes -- **needs modification** | Add binary scan target + pre-commit hook latency target |
| `/profile` | Performance | Yes | When benchmarks miss |
| `/build-cross` | Cross-platform | Yes | Every A gate |
| `/new-scanner` | Scaffolding | No | No new language scanners in Phase 4 |
| `/new-opengrep-rule` | Scaffolding | No | No new OpenGrep rules in Phase 4 |
| `/new-joern-query` | Scaffolding | No | No new Joern queries in Phase 4 |

**Python Backend (Workstream B):**

| Skill | Category | Applies to Phase 4? | Notes |
|---|---|---|---|
| `/lint-py` | Quality | Yes | All B milestones |
| `/test-py` | Quality | Yes -- **needs modification** | Add thresholds for LLM service, OTel receiver, HNDL model, agility score |
| `/sec-py` | Security | Yes | All B milestones |
| `/commit-py` | Workflow | Yes | Every B commit |
| `/new-api-route` | Scaffolding | Yes | B-M1 through B-M4 |
| `/db-migrate` | Database | Yes | B-M1 (attestation tables), B-M3 (OTel data) |
| `/db-validate` | Database | Yes | All B milestones |
| `/db-seed` | Database | Yes -- **needs modification** | Add OTel runtime data, LLM remediation examples, HNDL annotations |
| `/load-test` | Performance | Yes -- **needs modification** | Add LLM remediation latency target + OTel ingestion throughput |
| `/profile-py` | Performance | Yes | When load-test misses |
| `/webhook-test` | Integration | No | No new webhook work in Phase 4 |

**React Frontend (Workstream C):**

| Skill | Category | Applies to Phase 4? | Notes |
|---|---|---|---|
| `/lint-fe` | Quality | Yes | All C milestones |
| `/test-fe` | Quality | Yes -- **needs modification** | Add thresholds for remediation preview, runtime view, agility score, HNDL components |
| `/sec-fe` | Security | Yes | All C milestones |
| `/commit-fe` | Workflow | Yes | Every C commit |
| `/build-fe` | Quality | Yes | Bundle limit stays at 750KB (no new heavy deps) |
| `/new-page-fe` | Scaffolding | Yes | C-M1 through C-M3 |
| `/mock-api-fe` | Integration | Yes | C-M1 and C-M2 |
| `/a11y-fe` | Quality | Yes | All C milestones |

**Cross-workstream:**

| Skill | Category | Applies to Phase 4? | Notes |
|---|---|---|---|
| `/adr` | Architecture | Yes | 7 new ADRs before Phase 4 starts |
| `/openapi-sync` | Contract | Yes | B-M2, B-M3, C-M2 |
| `/docker-compose` | Infrastructure | Yes -- **needs modification** | Add OTel collector, LLM proxy sidecar |
| `/docker-build` | Infrastructure | Yes -- **needs modification** | Add OTel collector image, SonarQube plugin image, validate VS Code VSIX |
| `/e2e-test` | Integration | Yes -- **needs modification** | Add remediation preview, runtime enrichment view, IDE mock communication |
| `/changelog` | Documentation | Yes | Every milestone close |
| `/helm-validate` | Infrastructure | Yes | OTel collector deployment addition |
| `/helm-test` | Integration | Yes | Verify OTel + LLM proxy in k8s |

### Modified Skills (Phase 3 to Phase 4)

| Skill | Change | Reason |
|---|---|---|
| `/test-coverage` | Add thresholds: binary scanner 75%, pre-commit hook 85%, source/sink config 80% | New scanner packages |
| `/benchmark` | Add targets: JAR scan (50MB) < 30s; wheel scan (10MB) < 10s; pre-commit hook 100 files < 2s; single binary file (1MB) < 5s | Phase 4 performance criteria |
| `/test-py` | Add thresholds: LLM remediation service 80%, OTel receiver 80%, HNDL model 85%, agility score 85%, attestation service 80%, SBOM-CVE correlation 80% | New backend modules |
| `/test-fe` | Add thresholds: remediation preview 70%, runtime enrichment view 70%, agility score page 75%, HNDL risk page 75% | New complex UI components |
| `/db-seed` | Add: OTel runtime spans (50 per project), LLM remediation suggestions (100 across projects), HNDL data classification annotations, agility score inputs | Phase 4 test data |
| `/load-test` | Add targets: LLM remediation generation p95 < 5s; OTel span ingestion 1000 spans/s; SBOM-CVE correlation < 2s per CVE; attestation verification < 500ms | Phase 4 performance |
| `/docker-compose` | Add services: OTel collector (receives runtime spans), LLM proxy (rate limits + caches LLM calls), SonarQube dev instance (plugin testing) | Phase 4 infrastructure |
| `/docker-build` | Add images: `cipherradar/otel-collector:dev` (< 200MB), verify VS Code VSIX size < 10MB | OTel collector + VS Code |
| `/e2e-test` | Add test paths: remediation preview in finding detail -> accept/reject; runtime enrichment panel -> observed vs. configured; agility score -> drill-down; HNDL risk -> data classification | Phase 4 feature coverage |

### New Skills (Phase 4) -- 14 total

**Workstream A -- CLI:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/new-binary-rule` | Scaffolding | Scaffold a binary scanning detection rule: YARA rule definition in `cli/internal/scanner/binary/rules/`, test with known binary fixture, register in binary scanner rule set | Read existing binary scanner structure, create YARA rule + test fixture | A-M1 |
| `/binary-scan-test` | Integration | Validate binary scanning end-to-end: scan JAR file -> extract class files -> detect crypto constants; scan Python wheel -> detect crypto; scan ELF binary -> detect crypto constants. Tests against known binaries with embedded crypto | Build test JAR/wheel/ELF, `cradar scan --binary <file>`, validate CBOM output, verify crypto constant identification | A-M1, A-M2 |
| `/precommit-test` | Integration | Validate pre-commit hook: install hook in test repo, commit with hardcoded key -> blocked; commit clean code -> passes; measure latency on 100-file changeset < 2s | Create temp git repo, install hook, attempt commits, measure timing | A-M3 |

**Workstream B -- Backend + IDE:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/llm-test` | Integration | Validate LLM remediation generation: submit finding + code context, verify response contains valid code in correct language, verify idiomatic fix for detected library. Test with mock LLM provider to avoid API costs in CI | Mock LLM API, submit remediation request, validate response schema, check language correctness | B-M2 |
| `/otel-test` | Integration | Validate OpenTelemetry receiver: send OTLP spans with TLS/cipher attributes, verify spans are stored and linked to CBOM findings, verify enrichment appears in CBOM output | Start OTel collector, send test spans via `otel-cli` or gRPC client, query enriched CBOM, verify runtime fields populated | B-M3 |
| `/attestation-test` | Integration | Validate CBOM attestation: sign CBOM via Sigstore keyless, create Rekor transparency log entry, verify from fresh environment via `cosign verify-blob-attestation`. Extends Phase 3 `/signing-test` with full attestation envelope (in-toto format) | `cosign attest-blob`, `rekor-cli verify`, `cosign verify-blob-attestation` | B-M1 |
| `/vscode-build` | Quality | Build and validate VS Code extension: compile TypeScript, run extension tests (VS Code test runner), package VSIX, validate extension manifest, check VSIX size < 10MB | `cd extensions/vscode && npm run compile && npm test && npx vsce package`, verify `.vsix` artifact | B-M5 |
| `/vscode-test` | Integration | Test VS Code extension in headless mode: open a test project, trigger scan, verify inline diagnostics appear, verify hover shows quantum status, verify code action offers remediation | `npx vscode-test` with extension loaded, assert diagnostics on known test file | B-M5 |
| `/intellij-build` | Quality | Build and validate IntelliJ plugin: Gradle build, run plugin verification (IntelliJ Plugin Verifier), package distribution ZIP, validate plugin descriptor | `cd plugins/intellij && ./gradlew buildPlugin && ./gradlew verifyPlugin` | B-M6 |
| `/intellij-test` | Integration | Test IntelliJ plugin: run IDE tests via Gradle, verify external annotator produces annotations on known test file, verify gutter icon click opens finding detail | `cd plugins/intellij && ./gradlew test && ./gradlew runPluginVerifier` | B-M6 |
| `/sonarqube-plugin-build` | Quality | Build SonarQube plugin JAR (Gradle), validate plugin descriptor, test against SonarQube dev instance. (Carried from Phase 3 plan, now implemented) | `cd plugins/sonarqube && gradle build`, `sonar-scanner`, verify CBOM tab appears | B-M7 |

**Workstream C -- Frontend:**

| Skill | Category | Purpose | Commands | Milestones |
|---|---|---|---|---|
| `/remediation-preview-test` | Quality | Test remediation preview component: verify code diff rendering (before/after), verify accept/reject/edit actions, verify language-specific syntax highlighting, verify loading state during LLM generation | Render component with fixture data, interaction test via Vitest + Testing Library | C-M1 |
| `/runtime-view-test` | Quality | Test runtime enrichment view: verify observed vs. configured comparison table, verify gap highlighting (red when observed != configured), verify OTel span timeline visualization | Render component with fixture OTel data, verify table rows, verify gap indicators | C-M2 |

### New Hooks

| Hook | Trigger | Action |
|---|---|---|
| `npx vsce package --dry-run` | After any `.ts` file write/edit in `extensions/vscode/` | Validate extension compiles |
| `./gradlew check` | After any `.kt` file write/edit in `plugins/intellij/` | Validate plugin compiles |
| `./gradlew check` | After any `.kt`/`.java` file write/edit in `plugins/sonarqube/` | Validate SonarQube plugin compiles |

---

## Workstream A -- CLI: Binary Scanning + Pre-commit Hook + Custom Source/Sink Config (Go)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **A-M1** | Agent-BinaryScanner-Core | -- | No | Binary scanner core: `cli/internal/scanner/binary/`. Architecture: read file bytes, match against YARA-style rules for known crypto constants (AES S-box `63 7C 77 7B`, AES inverse S-box, DES S-boxes, SHA-256 round constants, RSA small primes, Blowfish P-array, Ed25519 base point). Use Go `regexp` + byte-level matching (no YARA dependency -- pure Go for single-binary distribution). Rule format: YAML definitions in `cli/internal/scanner/binary/rules/` embedded via `//go:embed`. Each rule: name, byte pattern (hex), algorithm, confidence, description. Implement `BinaryScanner` implementing the `Scanner` interface with extensions `.class`, `.jar`, `.whl`, `.so`, `.dylib`, `.dll`, `.exe`. For JAR/wheel: unzip first, scan inner files. Register as universal scanner for binary extensions. | `/new-binary-rule`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **A-M1** | Agent-BinaryScanner-JAR | -- | Yes | JAR-specific scanning: unpack JAR (ZIP format), scan `.class` files for crypto constants, scan `META-INF/MANIFEST.MF` for crypto-related entries, scan embedded resources (`.properties`, `.xml`) for algorithm configs. Report findings attributed to class file path within JAR. Handle nested JARs (Spring Boot fat JAR). | `/lint`, `/test-coverage`, `/binary-scan-test` |
| **A-M1** | Agent-BinaryScanner-Wheel | -- | Yes | Python wheel scanning: unpack `.whl` (ZIP format), scan `.so`/`.pyd` native extensions for crypto constants, scan `.py` files normally via existing Python scanner, scan `METADATA` and `RECORD` for crypto dependency references. Cross-reference with known crypto library wheel names (cryptography, pycryptodome, PyNaCl). | `/lint`, `/test-coverage`, `/binary-scan-test` |
| **A-M1** | **Orchestrator gate** | All A-M1 | -- | Binary scanner registered, JAR + wheel + native binary scanning functional, CBOM output valid | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz`, `/binary-scan-test`, `/build-cross` |
| **A-M2** | Agent-CustomSourceSink | A-M1 | No | Custom source/sink configuration: `.cradar.yml` extension to define custom crypto wrappers. Format: `custom_sources:` section listing function signatures with parameter positions that carry crypto material. Example: `- function: "com.myco.CryptoHelper.encrypt" params: [{pos: 1, type: "algorithm"}, {pos: 2, type: "key"}]`. Loader in `cli/internal/config/`. Pass 1 tree-sitter queries generated from config at scan time. Constprop applied to custom sources same as built-in. Test with a mock in-house crypto wrapper library. | `/lint`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **A-M2** | Agent-AgilityScore-CLI | A-M1 | Yes | Cryptographic Agility Score computation in CLI: analyze scan results to score each project 0-100 on crypto agility. Factors: (1) number of distinct call sites (fewer = more agile), (2) library abstraction level (wrapper vs. direct API), (3) algorithm diversity (single algorithm everywhere vs. mixed), (4) configuration externalization (hardcoded vs. config file), (5) PQC readiness of current algorithms. Output as part of CBOM `properties` and `cradar scan --format text` summary. Score formula weighted per factor with configurable weights in `.cradar.yml`. | `/lint`, `/test-coverage`, `/benchmark` |
| **A-M2** | **Orchestrator gate** | All A-M2 | -- | Custom source/sink config working, agility score computed and included in output | `/lint`, `/sec-review`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **A-M3** | Agent-PrecommitHook | A-M2 | No | Pre-commit hook: `cradar hook install` command installs a git pre-commit hook script. Hook runs `cradar hook scan` on staged files only. Detection: pure regex (no tree-sitter for speed) -- PEM private key headers, hex strings > 32 chars in assignment context, known API key patterns (AWS, GCP, Azure, GitHub PAT), base64-encoded keys. Exit code 1 blocks commit on hardcoded key detection. `--allow-pattern` flag for intentional patterns (test fixtures, docs). Performance target: 100 staged files in < 2s. `cradar hook scan` also available standalone. | `/lint`, `/sec-review`, `/test-coverage`, `/precommit-test`, `/build-cross` |
| **A-M3** | **Orchestrator gate** | A-M3 | -- | Full Workstream A close: binary scanning, custom source/sink, agility score, pre-commit hook | `/lint`, `/sec-review`, `/dep-audit`, `/test-coverage`, `/fuzz`, `/benchmark`, `/build-cross`, `/binary-scan-test`, `/precommit-test` |

---

## Workstream B -- Backend + IDE: LLM Remediation + Runtime Enrichment + SonarQube + IDE Plugins (Python/FastAPI + TypeScript + Kotlin)

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **B-M1** | Agent-CBOMAttestation | -- | No | CBOM attestation via Sigstore: extend existing signing service (`backend/app/services/signing_service.py`) to produce in-toto attestation envelopes wrapping the CBOM. Each scan produces an attestation (subject: CBOM SHA-256 digest, predicate: scan metadata -- tool version, timestamp, project, commit SHA). Keyless signing via Fulcio. Rekor transparency log entry per scan. Verification endpoint: `GET /api/v1/cbom/{id}/attestation/verify` returns verification status + Rekor log URL. Store attestation envelope alongside CBOM in CBOMStore. CLI `cradar verify <cbom.json>` command delegates to `cosign verify-blob-attestation`. | `/new-api-route`, `/lint-py`, `/sec-py`, `/test-py`, `/attestation-test`, `/db-migrate` |
| **B-M1** | Agent-SBOMCVECorrelation | -- | Yes | SBOM-CBOM CVE correlation: when a CVE is published for a crypto library, instantly show affected services. Extend SBOM service (`backend/app/services/sbom_service.py`) with CVE correlation engine. Ingest CVE data from OSV.dev API (free, covers NVD + GitHub advisories). Match CVEs to SBOM components via purl/CPE. When a crypto library CVE hits, cross-reference with CBOM to identify which crypto operations are affected. API: `GET /api/v1/cve/crypto?cve_id=CVE-XXXX-YYYY` returns affected services + specific crypto operations. Scheduled Taskiq worker polls OSV.dev daily. Notification trigger on new crypto-library CVE. | `/new-api-route`, `/lint-py`, `/sec-py`, `/test-py`, `/db-migrate` |
| **B-M1** | **Orchestrator gate** | All B-M1 | -- | Attestation verifiable via cosign, CVE correlation returns affected services | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/attestation-test` |
| **B-M2** | Agent-LLMRemediation | B-M1 | No | LLM-assisted remediation engine: `backend/app/services/llm_service.py`. Provider abstraction: `LLMProvider` interface with implementations for OpenAI (GPT-4o), Anthropic (Claude), and local/self-hosted (Ollama). Configurable via environment (`CRADAR_LLM_PROVIDER`, `CRADAR_LLM_API_KEY`, `CRADAR_LLM_MODEL`). Remediation request: takes finding + surrounding code (50 lines before/after) + imports + project language. System prompt engineering: role = "cryptography migration expert", constraints = "idiomatic for the detected library", output format = "JSON with `before`, `after`, `explanation`, `confidence`". Response caching (same finding + same code context = cached result, Redis TTL 24h). Rate limiting per org (configurable). Cost tracking per org. Never auto-apply: API returns suggestion only. API endpoints: `POST /api/v1/findings/{id}/remediation` (generate), `GET /api/v1/findings/{id}/remediation` (cached), `POST /api/v1/findings/{id}/remediation/accept` (mark accepted), `POST /api/v1/findings/{id}/remediation/reject` (mark rejected with reason). Acceptance tracking for the 60% success metric. | `/new-api-route`, `/lint-py`, `/sec-py`, `/test-py`, `/llm-test`, `/db-migrate` |
| **B-M2** | Agent-LLMPRComments | B-M1 | Yes (starts after Agent-LLMRemediation completes provider abstraction) | LLM remediation in PR comments: extend git provider integration (`backend/app/services/git_provider.py`) to post remediation suggestions as PR review comments. On scan triggered by webhook (push/PR), generate remediation for HIGH/CRITICAL findings, post as GitHub suggestion blocks / GitLab MR suggestions / Bitbucket PR comments. Respect per-org opt-in setting. Rate limit: max 5 remediation comments per PR (avoid noise). Format: code suggestion with explanation + quantum status. | `/lint-py`, `/test-py`, `/webhook-test` |
| **B-M2** | Agent-HNDLModel | B-M1 | Yes | "Harvest Now, Decrypt Later" risk model: `backend/app/services/hndl_service.py`. Risk formula: `HNDL_risk = data_sensitivity * quantum_vulnerability * time_factor`. `data_sensitivity`: user-annotated per-project/per-file classification (Public/Internal/Confidential/Restricted) via API + `.cradar.yml` `data_classification:` section. `quantum_vulnerability`: derived from existing quantum status (quantum-vulnerable = 1.0, quantum-safe = 0.0, quantum-unknown = 0.5). `time_factor`: configurable quantum timeline estimate (default: 2030 for symmetric, 2035 for asymmetric; user-overridable). Output: per-finding HNDL risk score (0-100), per-service aggregate, per-org aggregate. API: `GET /api/v1/projects/{id}/hndl-risk`, `PUT /api/v1/projects/{id}/data-classification`. Store data classification in project metadata. | `/new-api-route`, `/lint-py`, `/test-py`, `/db-migrate` |
| **B-M2** | **Orchestrator gate** | All B-M2 | -- | LLM remediation generates valid code, PR comments posted, HNDL model scores computed. OpenAPI spec updated. | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/llm-test`, `/openapi-sync` |
| **B-M3** | Agent-OTelReceiver | B-M2 | No | OpenTelemetry receiver: standalone Go service in `otel-receiver/` (or OTel Collector custom receiver plugin in `otel-receiver/`). Accepts OTLP gRPC and OTLP HTTP. Expected span attributes: `tls.protocol.version`, `tls.cipher_suite`, `net.peer.name`, `net.peer.port`, `http.scheme`. Receiver extracts crypto-relevant attributes, stores as runtime observations in PostgreSQL (new `runtime_observations` table: `id`, `project_id`, `org_id`, `service_name`, `observed_at`, `protocol`, `cipher_suite`, `tls_version`, `peer`, `span_id`, `trace_id`). Taskiq worker enriches CBOM: for each finding in the CBOM, look up matching runtime observations (same project + matching TLS config), annotate finding with `observed_protocol`, `observed_cipher_suite`, `gap_detected` (boolean: configured != observed). Enriched CBOM exposed via existing CBOM API (additional `runtime` field). API: `GET /api/v1/projects/{id}/runtime/summary` (observed cipher suites, TLS versions, gaps). | `/lint-py`, `/sec-py`, `/test-py`, `/otel-test`, `/db-migrate` |
| **B-M3** | Agent-AgilityScore-Backend | B-M2 | Yes | Cryptographic Agility Score backend: `backend/app/services/agility_service.py`. Receives agility factors from CLI scan output (embedded in CBOM properties by A-M2). Stores per-scan agility score in DB. Trending over time via TimescaleDB continuous aggregate. API: `GET /api/v1/projects/{id}/agility-score`, `GET /api/v1/portfolio/agility` (aggregate across projects). Weighted average for portfolio-level. | `/new-api-route`, `/lint-py`, `/test-py` |
| **B-M3** | **Orchestrator gate** | All B-M3 | -- | OTel receiver ingests spans, CBOM enriched with runtime data, agility score stored and trending. OpenAPI spec frozen for frontend. | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/otel-test`, `/openapi-sync` |
| **B-M4** | Agent-OWASPMASVSReport | B-M3 | No | OWASP MASVS compliance report: extend compliance service for mobile security. Map crypto findings in Swift/Dart/Kotlin/Java (mobile) projects to MASVS v2.0 controls: MASVS-CRYPTO-1 (strong crypto), MASVS-CRYPTO-2 (key management), MASVS-NETWORK-1 (TLS), MASVS-NETWORK-2 (certificate pinning detection). YAML rules in `scanner/library-models/owasp_masvs_v2.yml`. Score 0-100 per framework. PDF report generation. | `/lint-py`, `/test-py`, `/db-migrate` |
| **B-M4** | Agent-BackendPerformance-P4 | B-M3 | Yes | Performance validation: LLM remediation p95 < 5s (with caching), OTel span ingestion 1000 spans/s sustained, SBOM-CVE correlation < 2s per CVE, attestation verification < 500ms. Redis caching tuning for LLM responses. Connection pooling for OTel write path. Batch insert for OTel spans (not one-by-one). | `/lint-py`, `/test-py`, `/load-test`, `/profile-py` |
| **B-M4** | **Orchestrator gate** | All B-M4 | -- | OWASP MASVS report generates, performance targets met | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/load-test` |
| **B-M5** | Agent-VSCodeExtension | B-M2 | No | VS Code extension: `extensions/vscode/`. TypeScript + VS Code Extension API. Features: (1) Diagnostics provider -- reads CBOM JSON from workspace `.cradar/cbom.json` or fetches from CipherRadar API (configurable). Maps findings to VS Code `DiagnosticCollection` with severity/source. (2) Hover provider -- on hover over a finding location, shows: algorithm name, quantum status (color-coded), NIST level, confidence, remediation suggestion (from LLM API if available). (3) Code action provider -- "Fix with CipherRadar" action fetches LLM remediation and presents as a workspace edit. (4) Tree view -- sidebar panel showing finding summary grouped by severity. (5) Status bar item -- scan status + finding count. (6) Commands: `CipherRadar: Scan Workspace`, `CipherRadar: Show Findings`, `CipherRadar: Configure`. Settings: API URL, API key, auto-scan on save (off by default). Extension manifest (`package.json`) with activation events, contributes (commands, views, configuration). VSIX packaging. | `/vscode-build`, `/vscode-test`, `/lint-fe` |
| **B-M5** | **Orchestrator gate** | B-M5 | -- | VS Code extension builds, tests pass, VSIX < 10MB, diagnostics render on test project | `/vscode-build`, `/vscode-test` |
| **B-M6** | Agent-IntelliJPlugin | B-M5 | No | IntelliJ/JetBrains plugin: `plugins/intellij/`. Kotlin + IntelliJ Platform Plugin SDK (Gradle-based). Compatible with IntelliJ IDEA, WebStorm, PyCharm, GoLand (platform-level plugin, not IDE-specific). Features: (1) External annotator -- reads CBOM from local file or API, produces line-level annotations with severity-colored gutter icons. (2) Tooltip -- on hover: algorithm, quantum status, NIST level, remediation suggestion. (3) Quick fix -- "Apply CipherRadar Remediation" invokes LLM API and applies edit. (4) Tool window -- findings list with filtering (severity, quantum status, file). (5) Settings -- API URL, API key, local CBOM path. Plugin descriptor (`plugin.xml`). Marketplace metadata. Distribution ZIP. | `/intellij-build`, `/intellij-test` |
| **B-M6** | **Orchestrator gate** | B-M6 | -- | IntelliJ plugin builds, verification passes, annotations render on test project | `/intellij-build`, `/intellij-test` |
| **B-M7** | Agent-SonarQubePlugin | B-M4 | No | Full SonarQube plugin with CBOM tab (deferred from Phase 3 D-M3): `plugins/sonarqube/`. Java/Kotlin, Gradle build. Extends Phase 3 generic issue export. Plugin adds a dedicated "CBOM" tab to SonarQube project dashboard. Tab contents: (1) Finding summary table with quantum status column, (2) Algorithm distribution pie chart (rendered via SonarQube's built-in charting), (3) Compliance score badges per framework, (4) Agility score gauge. Plugin calls CipherRadar API to fetch latest CBOM + compliance + agility data. Authentication: API key stored in SonarQube project settings. SonarQube Marketplace metadata for publishing. | `/sonarqube-plugin-build`, `/lint` |
| **B-M7** | **Orchestrator gate** | B-M7 | -- | Full Workstream B close: attestation, CVE correlation, LLM remediation, OTel receiver, IDE plugins, SonarQube plugin | `/lint-py`, `/sec-py`, `/test-py`, `/db-validate`, `/load-test`, `/docker-build`, `/openapi-sync`, `/attestation-test`, `/vscode-build`, `/intellij-build`, `/sonarqube-plugin-build` |

---

## Workstream C -- Frontend: Remediation Preview + Runtime View + Agility Score + HNDL (React 19 + TypeScript)

**UI Reference:** `frontend/mockups/full-mockup-v2.html` remains the accepted mockup. Phase 4 frontend agents MUST extend the mockup for new pages.

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **C-M1** | Agent-RemediationPreview | -- | No | Remediation preview component in finding detail page: inline code diff view (before/after) with language-specific syntax highlighting (highlight.js or Prism -- already in project). "Generate Remediation" button triggers `POST /api/v1/findings/{id}/remediation` (mock API initially). Loading skeleton while LLM generates. Accept/Reject/Edit actions. Accepted remediation shows green check. Rejected shows reason input. Edit opens editable code block. Acceptance rate metric displayed on project settings page. Component in `frontend/src/components/findings/RemediationPreview.tsx`. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/mock-api-fe`, `/remediation-preview-test` |
| **C-M1** | Agent-HNDLRiskView | -- | Yes | HNDL risk model dashboard page: `frontend/src/pages/HNDLRisk/`. Portfolio-level view: heat map of services by HNDL risk score. Drill-down: per-project HNDL breakdown showing data sensitivity vs. quantum vulnerability vs. time factor. Data classification editor: inline edit data sensitivity per project (dropdown: Public/Internal/Confidential/Restricted). Quantum timeline slider (adjustable). Recharts for risk distribution. Table of highest-risk findings with HNDL score. Mock API. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/mock-api-fe` |
| **C-M1** | **Orchestrator gate** | All C-M1 | -- | Remediation preview renders, HNDL page renders, mock APIs serve data | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/mock-api-fe` |
| **C-M2** | Agent-RuntimeEnrichmentView | C-M1 | No | Runtime enrichment dashboard: `frontend/src/pages/RuntimeEnrichment/`. Per-project view: table of configured crypto (from CBOM) vs. observed crypto (from OTel). Columns: finding, configured algorithm/protocol, observed algorithm/protocol, gap (yes/no, highlighted red). Gap summary: count of mismatches, top-3 gaps. Timeline view: when was each cipher suite first/last observed (OTel span timeline). Filter by service name. Recharts for cipher suite distribution over time. Mock API. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/mock-api-fe`, `/runtime-view-test` |
| **C-M2** | Agent-AgilityScoreView | C-M1 | Yes | Cryptographic Agility Score page: `frontend/src/pages/AgilityScore/`. Per-project: radar chart showing 5 agility factors (call site count, abstraction level, algorithm diversity, config externalization, PQC readiness). Score gauge 0-100 with color bands (0-30 red, 30-60 yellow, 60-100 green). Trending line chart over time. Portfolio-level: bar chart of all projects ranked by agility score. Recommendations panel: "Improve score by X points: externalize algorithm config in project Y." Mock API. | `/new-page-fe`, `/lint-fe`, `/test-fe`, `/mock-api-fe` |
| **C-M2** | **Orchestrator gate** | All C-M2 | -- | Runtime enrichment and agility score pages render, gaps highlighted | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/a11y-fe`, `/mock-api-fe` |
| **C-M3** | Agent-FrontendAPIIntegration-P4 | C-M2 + **B-M3** | No | Replace mock API with live backend for all new Phase 4 pages. Regenerate TS types from frozen OpenAPI spec. Verify remediation preview, HNDL risk, runtime enrichment, agility score pages work against live data. Test LLM remediation round-trip (generate -> preview -> accept). Verify OTel runtime data renders. CORS config for new endpoints. | `/lint-fe`, `/test-fe`, `/openapi-sync`, `/mock-api-fe` |
| **C-M3** | Agent-VisualPolish-P4 | C-M2 | Yes | Visual regression: all 3 themes (Radar, Crystal, Sentinel) render correctly on all new pages. Screenshot baseline for visual regression. Remediation diff view theming (light/dark code blocks). Runtime gap highlighting theming. HNDL heat map theming. Bundle optimization check. | `/lint-fe`, `/test-fe`, `/build-fe`, `/a11y-fe` |
| **C-M3** | **Orchestrator gate** | All C-M3 | -- | Full Workstream C close: all new pages against live backend, all themes verified | `/lint-fe`, `/test-fe`, `/sec-fe`, `/build-fe`, `/a11y-fe`, `/docker-build`, `/openapi-sync` |

---

## Cross-Workstream Dependencies

```
A-M1 ─────► A-M2 ─────► A-M3                                (sequential within A)
B-M1 ─────► B-M2 ─────► B-M3 ─────► B-M4 ─────► B-M5 ─────► B-M6 ─────► B-M7   (sequential within B)
C-M1 ─────► C-M2 ─────► C-M3                                (sequential within C)
                          │     │
              C-M3 ◄──────┘     │     (C-M3 depends on B-M3 API freeze)
              B-M5 ◄── B-M2           (VS Code needs LLM remediation API)
              B-M7 ◄── B-M4           (SonarQube needs agility score + OTel data)
```

| Dependency | From | To | What |
|---|---|---|---|
| API contract freeze | B-M3 | C-M3 | Frontend integrates with live backend. B-M3 gate freezes OpenAPI spec for Phase 4 additions. |
| LLM remediation API | B-M2 | B-M5, C-M1 | VS Code extension and frontend remediation preview need the remediation endpoint. C-M1 uses mock, C-M3 switches to live. |
| OTel receiver API | B-M3 | C-M2 | Runtime enrichment view needs OTel data. C-M2 uses mock, C-M3 switches to live. |
| Agility score CLI output | A-M2 | B-M3 | Backend agility service reads agility factors from CLI-produced CBOM. |
| Binary scanner CLI binary | A-M1 | B-M7 | SonarQube plugin integration tests need binary scanning available. |
| HNDL model API | B-M2 | C-M1 | Frontend HNDL risk page needs the HNDL API. C-M1 uses mock. |
| Pre-commit hook binary | A-M3 | -- | No cross-workstream dependency. Standalone. |
| Shared assets | `scanner/library-models/` | A + B | Phase 4 adds `owasp_masvs_v2.yml`. Embedded at build time. |

---

## New ADRs Required

| ADR | Title | Workstream | Timing | Key Decision |
|---|---|---|---|---|
| ADR-026 | Binary Scanning Architecture -- byte-pattern matching vs. YARA vs. disassembly | A | Before A-M1 | Pure Go byte-pattern matching with YAML-defined rules embedded via `//go:embed`; no YARA dependency (single binary); no disassembly (crypto constants are data, not code) |
| ADR-027 | LLM Provider Abstraction -- multi-provider interface, caching, cost control | B | Before B-M2 | Common `LLMProvider` interface; OpenAI + Anthropic + Ollama implementations; Redis cache (TTL 24h); per-org rate limits + cost tracking; never auto-apply |
| ADR-028 | OpenTelemetry Runtime Enrichment Architecture -- collector plugin vs. standalone receiver | B | Before B-M3 | OTel Collector custom receiver plugin (Go) for ecosystem compatibility; OTLP gRPC + HTTP; store in PostgreSQL `runtime_observations` table; Taskiq worker enriches CBOM asynchronously |
| ADR-029 | IDE Extension Architecture -- LSP vs. diagnostics API, local vs. API mode | B | Before B-M5 | VS Code: Diagnostics API (not LSP, overhead not justified); IntelliJ: External Annotator API; both support dual mode: local CBOM file or backend API; same REST contract |
| ADR-030 | Pre-commit Hook Design -- regex-only for speed, no AST parsing in hook context | A | Before A-M3 | Pure regex matching in pre-commit context; no tree-sitter (too slow for commit-time); allow-pattern for intentional exclusions; < 2s on 100 files |
| ADR-031 | HNDL Risk Model -- formula, data classification taxonomy, quantum timeline assumptions | B | Before B-M2 | Multiplicative model: sensitivity * vulnerability * time_factor; 4-level classification (Public/Internal/Confidential/Restricted); configurable quantum timeline defaults |
| ADR-032 | CBOM Attestation Model -- in-toto envelope, Sigstore keyless, Rekor transparency | B | Before B-M1 | In-toto attestation envelope wrapping CBOM; extends Phase 3 cosign signing with attestation predicates; Rekor entry per scan; verifiable via `cosign verify-blob-attestation` |

---

## Orchestrator Rules

### Global (all workstreams)

1. **Never write implementation code.** Assign, coordinate, merge, validate only.
2. **Never hand off broken code.** Run lint + sec-review after every subagent.
3. **Parallel agents get the same base.** Clean build before launching parallel agents.
4. **Milestone-close gates are non-negotiable.** No exceptions.
5. **Escalate blockers immediately.** Surface to user before proceeding.

### Workstream A

6. Binary scanner reuses the `Scanner` interface. Register with specific binary extensions.
7. Binary scanner rules are YAML definitions, not hardcoded. New constants added by adding YAML rules.
8. Pre-commit hook is a separate `cradar hook` subcommand. Not a modification to `cradar scan`.
9. Custom source/sink config extends `.cradar.yml` -- not a separate config file.
10. Performance is non-negotiable: pre-commit hook < 2s on 100 files. Block milestone if missed.

### Workstream B

11. LLM remediation is never auto-applied. "Suggested" label always visible. No auto-merge into code.
12. LLM provider abstraction must support offline mode (Ollama) for air-gapped enterprises.
13. OTel receiver stores raw observations. CBOM enrichment is a separate async step (not in the hot path).
14. IDE extensions communicate via the same REST API as the dashboard. No special IDE-only endpoints.
15. SonarQube plugin is a thin API client -- no scanner logic in the plugin (same as ADR-021).
16. OpenAPI spec frozen at B-M3 before C-M3 begins.
17. Never store LLM API keys in the database. Environment variables only.
18. LLM response caching must be per-org to prevent information leakage between tenants.

### Workstream C

19. Strict TypeScript -- `strict: true`, no `any` except generated code.
20. Functional components only -- no class components.
21. TanStack Query for all server state -- no `useState` + `useEffect` fetch patterns.
22. Mock API for C-M1 and C-M2 -- real API integration only at C-M3.
23. All new pages must work in all 3 themes (Radar, Crystal, Sentinel).
24. Remediation preview code diff must use the project's existing syntax highlighting library -- no new highlighting dependency.

---

## Success Criteria Mapped to Gates

| Criterion | Gate | Workstream |
|---|---|---|
| Binary/JAR/wheel scanning produces valid CBOM | A-M1 gate | A |
| Custom source/sink configuration resolves in-house wrappers | A-M2 gate | A |
| Cryptographic Agility Score computed per project | A-M2 gate (CLI) + B-M3 gate (backend) | A + B |
| Pre-commit hook blocks hardcoded keys | A-M3 gate | A |
| Pre-commit hook completes in < 2s on 100 files | A-M3 gate | A |
| CBOM attestation verifiable via `cosign verify-blob-attestation` | B-M1 gate | B |
| SBOM-CBOM CVE correlation identifies affected services | B-M1 gate | B |
| LLM remediation generates valid code per language | B-M2 gate | B |
| LLM remediation acceptance rate > 60% (tracked via accept/reject API) | B-M7 gate (metric validation) | B |
| LLM remediation posted as PR comments | B-M2 gate | B |
| HNDL risk model scores computed per finding and per project | B-M2 gate | B |
| OTel receiver ingests runtime spans and enriches CBOM | B-M3 gate | B |
| Runtime enrichment highlights configured vs. observed gaps | B-M3 gate (backend) + C-M2 gate (frontend) | B + C |
| OWASP MASVS compliance report generates | B-M4 gate | B |
| VS Code extension published to Marketplace (or VSIX verified) | B-M5 gate | B |
| IntelliJ plugin published to JetBrains Marketplace (or ZIP verified) | B-M6 gate | B |
| SonarQube plugin with CBOM tab functional | B-M7 gate | B |
| Remediation preview renders in dashboard | C-M1 gate | C |
| HNDL risk dashboard renders with interactive classification | C-M1 gate | C |
| Runtime enrichment view shows configured vs. observed | C-M2 gate | C |
| Agility score page with radar chart and trending | C-M2 gate | C |
| All Phase 4 pages work against live backend | C-M3 gate | C |
| All 3 themes render correctly on all new pages | C-M3 gate | C |
| No HIGH/CRITICAL security findings | Every gate | All |
| All platforms build (CLI) | Every A gate | A |
| LLM remediation p95 < 5s | B-M4 gate | B |
| OTel ingestion throughput >= 1000 spans/s | B-M4 gate | B |

---

## Milestone Sequencing

```
Week 1-2:    A-M1 + B-M1 + C-M1                   (all start in parallel)
Week 3-4:    A-M2 + B-M2 + C-M1 (cont.)            (B-M2 starts after B-M1 gate)
Week 5-6:    A-M3 + B-M2 (cont.) + C-M2            (C-M2 starts after C-M1 gate)
Week 7-8:           B-M3 + C-M2 (cont.)             (B-M3 starts after B-M2 gate)
Week 9-10:          B-M3 (cont.) + C-M3             (C-M3 starts after B-M3 API freeze)
Week 11:            B-M4                              (OTel performance validation)
Week 12:            B-M5 (VS Code)                    
Week 13:            B-M6 (IntelliJ)
Week 14:            B-M7 (SonarQube)
Week 15:     Final integration                       (full stack verification)
```

### Week-by-Week Detail

| Week | Workstream A | Workstream B | Workstream C |
|---|---|---|---|
| 1 | A-M1: Binary scanner core + JAR scanning | B-M1: CBOM attestation + SBOM CVE correlation | C-M1: Remediation preview component |
| 2 | A-M1: Wheel scanning, gate | B-M1: gate | C-M1: HNDL risk page, gate |
| 3 | A-M2: Custom source/sink config | B-M2: LLM remediation engine | -- |
| 4 | A-M2: Agility score CLI, gate | B-M2: LLM PR comments + HNDL model | -- |
| 5 | A-M3: Pre-commit hook | B-M2: gate | C-M2: Runtime enrichment view |
| 6 | A-M3: gate | B-M3: OTel receiver | C-M2: Agility score page, gate |
| 7 | -- | B-M3: Agility score backend, gate (API freeze) | -- |
| 8 | -- | B-M4: OWASP MASVS + performance | C-M3: API integration |
| 9 | -- | B-M4: gate | C-M3: Visual polish, gate |
| 10 | -- | B-M5: VS Code extension | -- |
| 11 | -- | B-M5: gate | -- |
| 12 | -- | B-M6: IntelliJ plugin | -- |
| 13 | -- | B-M6: gate | -- |
| 14 | -- | B-M7: SonarQube plugin, gate | -- |
| 15 | Final integration: Docker Compose + Helm full stack, E2E tests, IDE plugins verified, changelog | | |

### Final Integration (Week 15)

Skills: `/docker-compose`, `/docker-build`, `/helm-validate`, `/helm-test`, `/e2e-test`, `/vscode-build`, `/intellij-build`, `/sonarqube-plugin-build`, `/changelog`

Validation:
1. `docker compose up` starts all services (API, frontend, scanner-worker, PostgreSQL, Redis, MinIO, notification worker, OTel collector, LLM proxy)
2. `helm install` to kind cluster starts all pods, passes health checks (including OTel collector)
3. `/e2e-test` -- Playwright: submit scan -> remediation preview on finding -> accept/reject -> HNDL risk page -> runtime enrichment view -> agility score -> attestation verification
4. `/binary-scan-test` -- binary scanning produces valid CBOM for JAR/wheel test fixtures
5. `/precommit-test` -- pre-commit hook blocks hardcoded key, passes clean code, completes in < 2s
6. `/vscode-build` -- VSIX packages, extension tests pass
7. `/intellij-build` -- plugin builds, verifier passes
8. `/sonarqube-plugin-build` -- CBOM tab renders in SonarQube dev instance
9. `/attestation-test` -- CBOM attestation verifiable via cosign
10. `/otel-test` -- OTel spans ingested, CBOM enriched with runtime data
11. `/load-test` -- LLM remediation p95 < 5s, OTel ingestion >= 1000 spans/s
12. `/changelog` -- generate release notes for Phase 4

Estimated duration: 15 weeks (Months 10-12 per roadmap, with 2-week buffer for IDE plugin marketplace review).

---

## New Skills Summary

| # | Skill Name | Category | Workstream | New? |
|---|---|---|---|---|
| 1 | `/new-binary-rule` | Scaffolding | A | New |
| 2 | `/binary-scan-test` | Integration | A | New |
| 3 | `/precommit-test` | Integration | A | New |
| 4 | `/llm-test` | Integration | B | New |
| 5 | `/otel-test` | Integration | B | New |
| 6 | `/attestation-test` | Integration | B | New |
| 7 | `/vscode-build` | Quality | B | New |
| 8 | `/vscode-test` | Integration | B | New |
| 9 | `/intellij-build` | Quality | B | New |
| 10 | `/intellij-test` | Integration | B | New |
| 11 | `/sonarqube-plugin-build` | Quality | B | New (was planned in Phase 3, now implemented) |
| 12 | `/remediation-preview-test` | Quality | C | New |
| 13 | `/runtime-view-test` | Quality | C | New |
| 14 | Total new skills | -- | -- | **13 new + 1 carried** |

---

## Directory Structure Additions

```
extensions/
  vscode/                  VS Code extension (TypeScript)
    src/
      extension.ts         Extension entry point
      diagnostics.ts       DiagnosticCollection provider
      hover.ts             HoverProvider for quantum status
      codeActions.ts       CodeActionProvider for LLM remediation
      treeView.ts          Findings sidebar tree view
      api.ts               CipherRadar API client
      config.ts            Extension settings
    test/
    package.json           Extension manifest
    tsconfig.json
    .vscodeignore

plugins/
  intellij/                IntelliJ/JetBrains plugin (Kotlin)
    src/main/kotlin/
      com/cipherradar/intellij/
        CipherRadarAnnotator.kt       External annotator
        CipherRadarToolWindow.kt      Tool window (findings list)
        CipherRadarQuickFix.kt        Quick fix (LLM remediation)
        CipherRadarSettings.kt        Plugin settings
        api/CipherRadarApiClient.kt   API client
    src/main/resources/
      META-INF/plugin.xml             Plugin descriptor
    build.gradle.kts
    settings.gradle.kts

  sonarqube/               SonarQube plugin (Java/Kotlin, from Phase 3 skeleton)
    src/main/java/
    build.gradle

otel-receiver/             OpenTelemetry collector receiver plugin (Go)
  go.mod
  factory.go
  receiver.go
  config.go
  receiver_test.go

cli/internal/scanner/binary/        Binary scanner package
  binary_scanner.go
  binary_scanner_test.go
  rules/                            Embedded YAML rule definitions
    aes_sbox.yml
    des_sbox.yml
    sha256_constants.yml
    rsa_primes.yml
    blowfish_parray.yml
    ed25519_basepoint.yml

cli/internal/hook/                  Pre-commit hook package
  hook.go
  hook_test.go
  patterns.go                       Regex patterns for key detection
  install.go                        Git hook installation

cli/internal/config/sourcesink/     Custom source/sink config
  loader.go
  loader_test.go

backend/app/services/
  llm_service.py                    LLM remediation engine
  llm_providers/
    __init__.py
    base.py                         LLMProvider interface
    openai_provider.py
    anthropic_provider.py
    ollama_provider.py
  hndl_service.py                   HNDL risk model
  agility_service.py                Agility score backend
  otel_service.py                   OTel data processing

scanner/library-models/
  owasp_masvs_v2.yml               OWASP MASVS compliance rules
```

---

### Critical Files for Implementation
- `/Users/cyberdevil/codeWorkspace/CipherRadar/cli/internal/scanner/scanner.go` - Core Scanner interface that the binary scanner must implement
- `/Users/cyberdevil/codeWorkspace/CipherRadar/backend/app/services/signing_service.py` - Existing signing service to extend with attestation envelope support
- `/Users/cyberdevil/codeWorkspace/CipherRadar/cli/internal/scanner/registry.go` - Registry where binary scanner must be registered
- `/Users/cyberdevil/codeWorkspace/CipherRadar/docs/13-phase3-implementation-plan.md` - Format reference for the plan document structure
- `/Users/cyberdevil/codeWorkspace/CipherRadar/backend/app/services/sbom_service.py` - Existing SBOM service to extend with CVE correlation
