# Changelog

All notable changes to CipherRadar are documented in this file.

---

## 0.2.0-rc.2 — 2026-05-18

### Bug fixes

- **Critical:** Pass 2 silently produced 0 findings when any rule file
  in the rules directory failed to load — restored via per-file
  pre-validation, skip-and-warn for broken files, and surfaced
  `output.Errors` from opengrep. (Bug 6)
- **High:** `cradar scan` on a missing or non-directory path no
  longer returns exit 0 + empty CycloneDX — now exits 3 with a
  specific message. (Bug 1)
- **High:** `cradar install-tools` fixed for linux/amd64 (was 404 on
  every fresh install) and now verifies SHA-256 of downloaded
  binaries against the GitHub Releases API `digest` field. See
  ADR-038. (Bug 5)
- **Medium:** OpenGrep findings' `RuleID` no longer carries the
  directory-derived namespace prefix; `--rules` and `--disable-rule`
  match opengrep findings correctly. (Bug 8)
- **Medium:** `--category bogus` now returns exit 3 (was exit 1).
  (Bug 2)
- **Low:** `--only-inventory` matched 0 findings without pass 2 emits
  a one-line hint pointing at `install-tools`. (Bug 4)
- **Low:** `--debug` and `--log-include-source` now produce
  per-scanner lifecycle events and per-finding emit events; source
  snippets are included only when the flag is set, truncated at 200
  chars. (Bug 3)

---

## 0.2.0-rc.1 — CLI Improvements Prerelease (2026-04-15)

First prerelease cut from `feature/cli-improvements`. Groups four
workstream items delivered against `docs/cli-improvements-plan.md`.

### Added
- **Rule lifecycle + category filters + baseline** (item 1, ADR-035):
  `--category`, `--only-inventory`, `--only-security`, `--rules`,
  `--disable-rule`, `--include-rule`, `--include-experimental`,
  `--include-noisy`, `--include-deprecated`. `.cradar-baseline.json`
  with `--update-baseline` / `--no-baseline`. New `cradar rules list`
  and `cradar rules explain` subcommands.
- **Structured logging + validator enrichment** (item 2, ADR-036):
  `cli/pkg/log` (stdlib `log/slog`), per-run JSONL at
  `~/.cradar/logs/cradar-<ts>-<pid>.log.jsonl`, retention cap of 10,
  path redaction against scan root. Flags: `--verbose`, `--debug`,
  `--quiet`, `--log-file`, `--log-format`, `--log-include-source`.
  Validator now surfaces keyword / actual / expected per leaf error.
- **Exit-code contract** (ADR-036): typed `ExitError` with documented
  codes 0 (clean), 1 (findings at/above `--fail-on`), 2 (warnings),
  3 (config/schema error), 4 (required tool missing). `--fail-on`
  now aggregates every offender instead of stopping at the first.
- **Multi-output formats** (item 3, ADR-037): `--output` is
  repeatable; format inferred from file extension (`.cbom.json`,
  `.cdx.json`, `.cyclonedx.json`, `.sonar.json`, `.sarif`, `.pdf`,
  `.txt`). New `table` writer for row-level findings. TTY-aware
  stdout default (text on terminal, cyclonedx-json on pipe).
  `.cradar.yml` `default_format` is finally honored.
- **Quick-wins bundle** (item 4): `cradar completion` for
  bash/zsh/fish/powershell. `cradar init` scaffolds `.cradar.yml`
  and `policy.cradar.yml` with commented defaults (supports `--force`
  and `--dir`). `--deep` / `--passes 2` now exits code 4 when
  opengrep is missing, matching the exit-code contract.

### Changed
- Custom wrappers configured via `.cradar.yml` `custom_wrappers:` are
  finally registered in `scannerinit/defaults.go` (previously a silent
  no-op).
- Schema validator walks the full `jsonschema.ValidationError.Causes`
  tree and emits only leaf errors with JSON Pointer paths.
- Default scan no longer runs the ~9 `hardcoded-*` rule family (moved
  to `maturity: experimental`, `default_enabled: false`); opt in via
  `--include-experimental --include-noisy`.

### Fixed
- `--verbose` flag now actually does something (was dead-declared on
  `rootCmd` with no reader).
- `os.Exit` calls in `policy.go` replaced with typed exits so deferred
  cleanup (temp dirs, log flushes) runs on failure.
- Single-argument `--output` no longer silently drops later `-o`
  values; the flag is now a proper `StringSlice`.

### Removed
- `contains` / `searchString` hand-rolled helpers in `hook.go`;
  replaced with `strings.Contains`.

### ADRs
- [ADR-035](docs/decisions/ADR-035-rule-lifecycle-and-deprecation-policy.md) — Rule Lifecycle & Deprecation Policy.
- [ADR-036](docs/decisions/ADR-036-structured-logging-and-exit-codes.md) — Structured Logging, Redaction Defaults, Exit-Code Contract.
- [ADR-037](docs/decisions/ADR-037-multi-output-and-format-dispatch.md) — Multi-Output Sinks, Extension Dispatch, TTY-Aware Defaults.

---

## Phase 4 — Differentiation (Complete — 2026-03-22)

### Workstream A — CLI: Binary Scanning + Pre-commit Hook + Custom Source/Sink Config (Go)
- Binary scanner: JAR (including Spring Boot fat JARs), Python wheel (.whl), and native ELF/dylib/DLL scanning for crypto constants (AES S-box, DES S-boxes, SHA-256 round constants, RSA primes, Blowfish P-array, Ed25519 base point)
- Pure Go byte-pattern matching with YAML-defined rules embedded via `//go:embed` (no YARA dependency)
- Custom source/sink configuration via `.cradar.yml` for in-house crypto wrappers
- Cryptographic Agility Score (0-100) computed per project with 5 weighted factors: call site count, abstraction level, algorithm diversity, config externalization, PQC readiness
- Pre-commit hook: `cradar hook install` / `cradar hook scan` — pure regex for speed, blocks hardcoded keys (PEM headers, hex strings, API key patterns), < 2s on 100 files
- ADR-024: `cbom` renamed to `cradar` (legacy alias retained)
- ADR-025: `--push` flag for uploading scan results to portal

### Workstream B — Backend + Plugins: LLM Remediation + Runtime Enrichment + IDE Plugins + SonarQube (Python/FastAPI + TypeScript + Kotlin)
- CBOM attestation via Sigstore: in-toto attestation envelopes, keyless signing via Fulcio, Rekor transparency log entry per scan, verifiable via `cosign verify-blob-attestation`
- SBOM-CBOM CVE correlation: OSV.dev integration, daily polling, instant identification of affected services when crypto library CVEs are published
- LLM-assisted remediation engine: provider abstraction (Anthropic/OpenAI/Ollama), Redis-cached responses, per-org rate limiting and cost tracking, accept/reject tracking
- LLM remediation posted as PR comments (GitHub suggestion blocks, GitLab MR suggestions, Bitbucket PR comments)
- "Harvest Now, Decrypt Later" (HNDL) risk model: multiplicative formula (sensitivity * vulnerability * time_factor), 4-level data classification (Public/Internal/Confidential/Restricted), configurable quantum timeline
- OpenTelemetry runtime enrichment: custom OTel collector receiver (Go), OTLP gRPC + HTTP, stores runtime observations, async CBOM enrichment highlighting configured vs. observed gaps
- Cryptographic Agility Score backend: per-project trending via TimescaleDB, portfolio-level aggregation
- CamelCase API response format (Pydantic alias_generator)
- OWASP MASVS v2.0 compliance report for mobile projects
- VS Code extension: diagnostics provider, hover (quantum status), code actions (LLM remediation), findings tree view, VSIX packaged
- IntelliJ/JetBrains plugin: external annotator, gutter icons, quick fix (LLM remediation), tool window, compatible with IDEA/WebStorm/PyCharm/GoLand
- Full SonarQube plugin with CBOM tab: finding summary, algorithm distribution, compliance scores, agility score gauge (deferred from Phase 3 D-M3)

### Workstream C — Frontend: Remediation Preview + Runtime View + Agility Score + HNDL (React 19 + TypeScript)
- Remediation preview component: inline code diff (before/after) with syntax highlighting, accept/reject/edit actions
- Runtime enrichment dashboard: configured vs. observed crypto comparison table, gap highlighting, OTel span timeline, cipher suite distribution over time
- Cryptographic Agility Score page: radar chart (5 factors), score gauge (0-100), trending line chart, portfolio bar chart, recommendations panel
- HNDL risk dashboard: portfolio heat map, per-project drill-down, inline data classification editor, quantum timeline slider
- CVE correlation view: affected services per crypto library CVE
- Route + RBAC wiring for all new pages
- All pages verified across 3 themes (Radar, Crystal, Sentinel)
- Live backend integration (mock API replaced)

### ADRs Accepted
- ADR-026: Binary scanning architecture — pure Go byte-pattern matching with embedded YAML rules
- ADR-027: LLM provider abstraction — multi-provider interface, caching, cost control
- ADR-028: OpenTelemetry runtime enrichment — OTel Collector custom receiver plugin
- ADR-029: IDE extension architecture — VS Code Diagnostics API, IntelliJ External Annotator API
- ADR-030: Pre-commit hook design — regex-only for speed, no AST parsing
- ADR-031: HNDL risk model — multiplicative formula, 4-level classification, configurable quantum timeline
- ADR-032: CBOM attestation model — in-toto envelope, Sigstore keyless, Rekor transparency

---

## Phase 3 — Enterprise (Complete — 2026-03-21)

### Week 1-2: A-M1 + B-M1 + C-M1 + D-M1
- 5 new language scanners: C/C++ (OpenSSL, libsodium, mbedTLS), Rust (ring, rustls), Swift (CryptoKit, CommonCrypto), Ruby (OpenSSL, BCrypt, Digest), Dart (package:crypto, pointycastle)
- 12 languages total with 15 new OpenGrep taint rules
- Multi-tenant RBAC: PostgreSQL RLS, 7-role enforcement, group hierarchy
- Portfolio dashboard with heat map + asset explorer
- Helm chart (15 templates) + Kustomize manifests (dev/staging/prod overlays)

### Week 3-4: A-M2 + B-M2 + C-M2
- CLI renamed from `cbom` to `cradar` (ADR-024) with `cbom` legacy alias
- `cradar scan --push` flag for uploading results to portal (ADR-025)
- Joern CPG deep analysis for C/C++ (inter-procedural OpenSSL/libsodium)
- Config file expansion: nginx.conf, httpd.conf, openssl.cnf, java.security, k8s manifests, Dockerfiles
- 4 new compliance frameworks: PCI-DSS v4.0, NSA CNSA 2.0 (with timeline tracker), ISO 27001:2022 A.8.24, EU Cyber Resilience Act
- Compliance score trending over time (TimescaleDB hypertable with daily/weekly/monthly roll-ups)
- SBOM ingestion + CBOM-SBOM component linking (CycloneDX and SPDX)
- Scan upload endpoint (`POST /api/v1/scans/upload`) for CLI `--push`
- D3.js force-directed dependency graph (Canvas rendering, 500+ nodes)
- Certificate expiry calendar with color-coded urgency
- Compliance dashboard with per-framework score cards and drill-down
- CBOM diff view with side-by-side snapshot comparison

### Week 5-7: A-M3 + B-M3 + C-M3 + D-M2
- Container image layer scanning (OCI image → extract + scan filesystem via go-containerregistry)
- Notification engine: in-app (WebSocket), email (SMTP + Jinja2), Microsoft Teams (Adaptive Cards)
- Jira integration: OAuth 2.0, auto-create tickets on policy violations, deduplication
- CBOM signing via Sigstore/cosign with Rekor transparency log
- Migration Kanban board (drag-and-drop, quantum migration tasks)
- Notification center UI (bell icon, preferences, real-time WebSocket push)
- Frontend API integration for all Phase 3 pages (live backend replaces mock API)
- Sigstore infrastructure in scanner-worker image (keyless signing, Fulcio + Rekor)

### Week 8-12: B-M4 + C-M4 + D-M3 + D-M4
- Portfolio API with Redis caching (`/api/v1/portfolio/summary`, `/portfolio/compliance`, `/portfolio/quantum`)
- Backend performance validation (50-repo portfolio < 2s, notification dispatch < 100ms)
- Multi-tenant frontend: role-based nav visibility, org switcher, admin settings, user management, audit log
- Visual polish and theme verification across all 3 themes (Radar, Crystal, Sentinel)
- SonarQube generic issue export (`cradar scan --format sonarqube-generic`)
- Dependency-Track integration (CBOM export + auto-upload + vulnerability correlation)
- Prometheus metrics endpoint
- Scale validation: 50-repository portfolio scan within 30 minutes (parallel Taskiq workers)
- SOC 2 Type II controls: audit logging, encryption at rest/transit, access controls, monitoring

### Docker Deployment
- Full stack Docker Compose with seed data, auto-migrations, default admin
- Services: TimescaleDB, Redis, FastAPI API, React frontend (nginx)
- Default credentials: admin@cipherradar.local / admin123
- Frontend: http://localhost:3001, API: http://localhost:8001/api/v1/health

---

## Phase 2 — Coverage + Risk (2026-03-20)

### Workstream A — CLI: More Languages + Detection (Go)
- Added Go scanner: `crypto/*` stdlib, `golang.org/x/crypto` (chacha20poly1305, nacl, argon2, bcrypt, scrypt, ssh, hkdf)
- Added Kotlin scanner: reuses Java library models (JCA/JCE, Bouncy Castle) with Kotlin-specific extensions
- Added C# scanner: `System.Security.Cryptography` (Aes, RSA, ECDsa, SHA256, HMAC, Rfc2898DeriveBytes), BouncyCastle.NET
- Added PHP scanner: `openssl_*`, `hash_*`, `password_hash`, `sodium_*`
- Joern Pass 3 integration: inter-procedural CPG analysis for Java, Python, JS (optional, `--deep` flag)
- Detection expansion: certificate parsing/expiry, JWT/JOSE `alg` detection, PBKDF2/bcrypt/scrypt/Argon2 iteration checks, ECB mode detection, PKCS1v15 flagging
- OpenGrep rules for Go, Kotlin, C#, PHP (hardcoded key, static IV, weak PRNG)

### Workstream B — Backend: API + Data (Python/FastAPI)
- FastAPI backend with SQLAlchemy 2.0 async, Alembic migrations, Taskiq workers
- PostgreSQL 17 + TimescaleDB for scan metrics
- JWT authentication with refresh tokens, API keys for CI/CD
- 7 RBAC roles (Org Admin, Security Manager, Security Engineer, Team Manager, Compliance Auditor, Developer, Guest)
- Scan API: submission, status polling, CBOM retrieval via CBOMStore abstraction
- Git hosting integrations: GitHub (OAuth, webhooks, Checks API), GitLab (OAuth, webhooks, MR notes), Bitbucket Cloud + Data Center
- Compliance engine: NIST SP 800-131A, FIPS 140-3, Quantum Risk Score (0-100), Migration Priority Queue
- CBOM management: versioning (immutable snapshots), diff API, merge API
- Report generation: PDF (ReportLab), HTML (Jinja2), Excel/CSV (openpyxl) via Taskiq background tasks
- Performance: CBOM retrieval < 200ms with GIN indexes + Redis caching

### Workstream C — Frontend: Dashboard (React 19 + TypeScript)
- React 19 + TypeScript strict mode with shadcn/ui + Tailwind CSS
- TanStack Query + Router for server state and routing
- 3 themes: Radar (SOC dark, cyan), Crystal (clean SaaS, purple), Sentinel (data-dense, amber)
- Login page with email/password, GitHub SSO, SAML/OIDC
- Dashboard with repository list, scan history, finding list with filters
- Repository detail: Overview, Scans, Findings, CBOM Diff, Quantum, Compliance sub-pages
- Quantum readiness view: risk score gauge, algorithm breakdown, PQC migration priority, trends
- Compliance view: per-framework scores, gap list, PDF download
- Settings: org config, integrations, API keys, audit log
- My Profile: theme selection, notification preferences, password/MFA
- RBAC-driven navigation visibility (7 roles)
- MSW mock API for development, replaced with live backend integration

### Infrastructure
- Docker Compose full stack: TimescaleDB, Redis, FastAPI API, React frontend (nginx)
- Backend Dockerfile: Python 3.12-slim, non-root user
- Frontend Dockerfile: multi-stage build (node build + nginx serve)
- Nginx reverse proxy with SPA fallback and API proxying

---

## Phase 1 — Foundation (2026-03-18)

### Scanner Core
- tree-sitter integration with language detection and dispatch
- AST-based detection for Java, Python, JavaScript/TypeScript (3 languages)
- Library API models: JCA/JCE, Bouncy Castle, Python `cryptography`/`hashlib`, Node.js `crypto`/`jsonwebtoken`
- Regex layer: PEM headers, key blobs, algorithm name strings
- Config file scanner: `.env`, `*.properties`, basic YAML
- Pass 1: constant propagation (intra-procedural variable tracking + project-wide symbol table)
- Pass 2: OpenGrep taint rules (16 rules: 6 Java, 5 Python, 5 JS)
- Confidence scoring (High / Medium / Low / Unresolved)

### Output
- CycloneDX 1.7 JSON with full `cryptoProperties`
- SARIF 2.1 output
- Text summary to terminal
- PDF detailed report (Go `maroto` library)

### Policy Engine
- YAML policy file parsing with 6 rule types
- `PASS` / `FAIL` / `WARN` exit codes for CI/CD
- `--fail-on CRITICAL` flag

### CLI Commands
- `cbom scan`, `cbom diff`, `cbom policy check`, `cbom report`
- `cbom install-tools` for OpenGrep download

### CI/CD
- GitHub Actions composite action
- GitLab CI template

### Distribution
- GoReleaser: `cbom` (lightweight ~15MB) and `cbom-full` (bundled OpenGrep ~80-100MB)
- 5 platforms: macOS/Linux amd64+arm64, Windows amd64
