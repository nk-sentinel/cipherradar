# Changelog

All notable changes to CipherRadar are documented in this file.

---

## Phase 3 — Enterprise (In Progress)

### Week 1-2: A-M1 + B-M1 + C-M1 + D-M1
- 5 new language scanners: C/C++ (OpenSSL, libsodium, mbedTLS), Rust (ring, rustls), Swift (CryptoKit, CommonCrypto), Ruby (OpenSSL, BCrypt, Digest), Dart (package:crypto, pointycastle)
- 12 languages total with 15 new OpenGrep taint rules
- Multi-tenant RBAC: PostgreSQL RLS, 7-role enforcement, group hierarchy
- Portfolio dashboard with heat map + asset explorer
- Helm chart (15 templates) + Kustomize manifests (dev/staging/prod overlays)

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
