# Features

> **Document version:** v2
> **Created:** 2026-03-15
> **Last updated:** 2026-03-17
> **Status:** Active

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-15 | Initial document — Feature Sets 1–10 | — |
| v2 | 2026-03-17 | Added Feature Sets 11–13 (Source History & Infrastructure, Developer Quality & Ownership, Extended Platform & AI) | Design session 2026-03-17 |

---

## Feature Set 1: Core Scanner

| Feature | Description |
|---|---|
| Multi-language scanning | 12+ languages via pluggable language analyzers backed by tree-sitter |
| Git repository scanning | Clone and scan any Git URL (GitHub, GitLab, Bitbucket, self-hosted) |
| Local path scanning | `cbom scan ./myproject` — zero configuration required |
| Differential scanning | Scan only changed files since last commit; fast incremental mode |
| Branch-aware scanning | Scan multiple branches; compare CBOM between main and a PR branch |
| Monorepo support | Detect sub-modules independently; emit per-module + aggregated CBOM |
| Container image scanning | Extract OCI image layers; scan certs, JARs, binaries for crypto constants |
| Config file scanning | nginx.conf, httpd.conf, openssl.cnf, JVM security properties, k8s manifests |
| Dependency correlation | Cross-reference detected library calls with SBOM; link CBOM assets to SBOM components |
| Confidence levels | High / Medium / Low / Unresolved per finding |
| Exact code location | File path, line number, column, code snippet for every finding |
| False positive suppression | Inline `// cbom-ignore` comments and `.cbomignore` rules file |

---

## Feature Set 2: CBOM Management

| Feature | Description |
|---|---|
| CycloneDX 1.7 output | Full-spec JSON and XML; all `cryptoProperties` fields populated |
| CBOM versioning | Every scan creates a versioned snapshot; full history retained |
| CBOM diff / changelog | What changed between scan A and scan B — new, resolved, changed |
| CBOM merge | Merge CBOMs from multiple repos into a portfolio-level CBOM |
| CBOM dependency graph | Visual graph: service → library → algorithm → key material |
| SPDX export | SPDX 3.0 format with crypto annotations |
| SARIF export | For IDE and CI/CD tool consumption |
| Custom JSON/CSV export | Flat export for spreadsheet-based compliance teams |
| CBOM signing | Sign CBOM documents via Sigstore/Rekor for audit integrity |
| SBOM integration | Ingest existing SBOM; enrich with CBOM data; output combined xBOM |

---

## Feature Set 3: Risk & Quantum Readiness

| Feature | Description |
|---|---|
| Quantum Vulnerability Classification | `quantum-vulnerable` (RSA, ECC, DH, DSA), `quantum-safe` (AES-256, SHA-3, ML-KEM), `quantum-unknown`, `broken` |
| NIST Quantum Security Level scoring | Map every algorithm to NIST PQC security level 0–6 |
| Quantum Risk Score per service | Aggregate quantum-vulnerable count weighted by usage frequency |
| Migration Priority Queue | Rank services by quantum migration urgency |
| "Harvest Now, Decrypt Later" risk flag | Flag algorithms protecting long-lived/high-value data as highest priority |
| PQC Readiness Report | % quantum-safe, migration gaps, effort estimate |
| Migration path suggestions | For each quantum-vulnerable algorithm, suggest PQC replacement |
| Hybrid scheme advisor | Suggest classical + PQC hybrid schemes where pure PQC is not yet feasible |
| NIST IR 8547 deadline tracker | Countdown to 2030 deprecation and 2035 disallowed deadlines |

---

## Feature Set 4: Cryptographic Misuse Detection

Every misuse finding includes: CWE mapping, OWASP reference, severity, remediation guidance, code location.

| Finding | Severity | Detection Method |
|---|---|---|
| Weak algorithm (DES, 3DES, RC4, Blowfish, MD5 for security) | Critical | AST — algorithm name match |
| ECB mode | Critical | AST — mode parameter |
| Static IV / nonce reuse | Critical | Taint — constant → IV parameter |
| Hardcoded key material | Critical | Taint + Regex — constant → key parameter |
| Weak PRNG for security use (`Math.random`, `rand()`, `Random`) | Critical | Taint — PRNG sink |
| Short key size (RSA < 2048, EC < 224, AES < 128) | High | AST — key size parameter |
| Disabled certificate validation | Critical | AST — empty TrustManager, `verify=False` |
| PKCS1v15 padding for RSA encrypt | High | AST — padding parameter |
| Insufficient KDF iterations (PBKDF2 < 600k, bcrypt cost < 12) | High | AST — iteration count |
| Unauthenticated encryption (CBC/CTR without MAC) | High | AST — mode without integrity |
| JWT `alg: none` | Critical | AST — JWT library `none` algorithm |
| MD5 / SHA-1 for password hashing | Critical | AST — hash function for password |
| Static salt to KDF | High | Taint — constant → salt parameter |
| Deprecated TLS version (TLS 1.0, 1.1, SSLv3) | High | AST / Config — protocol version |
| Expired certificate | Critical | Certificate parsing — notValidAfter |
| Expiring certificate (≤ 30 days) | High | Certificate parsing — notValidAfter |
| Self-signed certificate in production context | Medium | Certificate parsing — issuer == subject |
| Unauthenticated algorithm selection (JWT alg not validated) | High | Taint — `alg` from token header |

---

## Feature Set 5: Compliance Mapping Engine

| Framework | What Gets Mapped |
|---|---|
| NIST SP 800-131A Rev. 3 | Every algorithm → Acceptable / Deprecated / Disallowed status |
| FIPS 140-2 / 140-3 | Non-FIPS-approved algorithms; unapproved mode/padding combinations |
| PCI-DSS v4.0 | Requirements 4, 8, 12 — strong crypto, key inventory, policy |
| NSA CNSA 2.0 | Compare inventory against mandated algorithm set; CNSA 2.0 timeline compliance |
| NIST CSF 2.0 | Map to Identify and Protect functions |
| ISO 27001:2022 | A.8.24 — Use of Cryptography |
| EU Cyber Resilience Act | SBOM/CBOM gaps required for CRA compliance (Dec 2027) |
| SOC 2 Type II | CC6 — Logical and Physical Access Controls |
| Custom policy engine | Define your own prohibited/required algorithms in YAML |

**Compliance outputs per framework:**
- Number of violations
- Affected assets and locations
- Severity distribution
- Compliance score (0–100)
- Audit evidence package (signed CBOM + scan metadata + policy results)

---

## Feature Set 6: Policy Engine

Policy rules are defined in YAML and evaluated on every scan. CI/CD pipelines can gate on `FAIL` results.

```yaml
# policy.cbom.yml
name: "Enterprise Crypto Policy v2.0"
version: "2.0"
rules:
  - id: NO_WEAK_SYMMETRIC
    description: "DES, 3DES, RC4, Blowfish are prohibited"
    match:
      assetType: algorithm
      algorithmFamily: [DES, "3DES", RC4, Blowfish]
    action: FAIL
    severity: CRITICAL

  - id: MIN_AES_KEY_SIZE
    description: "AES key size must be at least 256 bits"
    match:
      assetType: algorithm
      algorithmFamily: AES
      keySize: { lt: 256 }
    action: WARN
    severity: HIGH

  - id: NO_TLS_BELOW_1_2
    description: "TLS versions below 1.2 are prohibited"
    match:
      assetType: protocol
      protocolType: tls
      version: ["1.0", "1.1", "SSLv3"]
    action: FAIL
    severity: CRITICAL

  - id: REQUIRE_QUANTUM_SAFE_KEM
    description: "All KEM operations must use PQC-safe algorithms"
    match:
      assetType: algorithm
      cryptoFunction: [encapsulate, decapsulate]
      nistQuantumSecurityLevel: { lt: 1 }
    action: WARN
    severity: HIGH

  - id: NO_STATIC_IV
    description: "IV/nonce must not be a static constant"
    match:
      assetType: relatedCryptoMaterial
      materialType: initializationVector
      isDynamic: false
    action: FAIL
    severity: CRITICAL
```

---

## Feature Set 7: CI/CD & Developer Integration

| Integration | Capabilities |
|---|---|
| GitHub Actions | `cbom-action` — scan on push/PR; post findings as PR review comments; policy as required check |
| GitLab CI | Native CBOM stage; SARIF to GitLab security dashboard |
| Jenkins plugin | Post-build CBOM step; archive CBOM artifact; policy gate |
| Pre-commit hook | Lightweight regex scan before commit; blocks hardcoded keys |
| VS Code extension | Inline CBOM findings in editor; hover for algorithm details + quantum status |
| IntelliJ / JetBrains plugin | Line-level annotations; crypto misuse highlighting |
| SonarQube plugin | CBOM tab in SonarQube security dashboard |
| Dependency-Track | Push CBOM to Dependency-Track for portfolio management |
| Jira integration | Auto-create tickets for policy violations with pre-filled remediation |
| Slack / Teams | Alert on new Critical findings or policy failures |
| REST API + OpenAPI 3.1 | Full programmatic access to all scanner functionality |

---

## Feature Set 8: Dashboard & Visualisation

| View | Content |
|---|---|
| Portfolio Dashboard | All repositories; heat map of crypto risk score; quantum readiness % by service |
| Asset Explorer | Searchable, filterable inventory of all crypto assets across the portfolio |
| Algorithm Distribution | Pie/bar charts: algorithm families, quantum-safe vs. vulnerable split |
| Dependency Graph | Interactive: service → library → algorithm → key material |
| Timeline / Trend View | Crypto posture change over time; new/resolved/still-open findings |
| CBOM Diff View | Side-by-side diff of two scan snapshots |
| Compliance Dashboard | Per-standard compliance score with drill-down by violation |
| Migration Kanban | Quantum migration tasks: TO DO / IN PROGRESS / DONE |
| Certificate Expiry Calendar | Calendar view of certificate expiration dates; upcoming expirations highlighted |
| Repository Detail | Deep dive: all findings by file, category, risk level |
| Finding Detail | Algorithm name, parameters, code snippet, location, risk, fix, CWE/OWASP links |

---

## Feature Set 9: Reporting

| Report | Audience | Format |
|---|---|---|
| CBOM Artifact | Tools / downstream systems | CycloneDX 1.7 JSON/XML |
| Executive Summary | CISO, CTO | PDF — 2-page: risk score, quantum gap, top issues |
| Compliance Gap Report | GRC / Auditors | PDF / Excel — per-standard breakdown |
| PQC Readiness Report | Security Architect, Platform Engineering | PDF — full algorithm inventory + migration roadmap |
| Developer Findings Report | AppSec / Dev teams | HTML / SARIF — file-level findings with code snippets |
| Audit Evidence Package | External auditors | Signed CBOM + scan metadata + policy results |
| Migration Effort Estimate | Engineering Management | Table: N instances of X algorithm, estimated migration effort |
| Trend Report | Security team | Posture change over last 30/60/90 days |

---

## Feature Set 10: Advanced / Differentiating Features

| Feature | Description |
|---|---|
| Cryptographic Agility Score | Measure how easily algorithms can be swapped — tight coupling to a single library scores lower |
| SBOM ↔ CBOM CVE correlation | When a CVE hits a crypto library, instantly show affected services and their crypto usage |
| "Harvest Now, Decrypt Later" risk model | Flag encrypted data with risk window beyond 2030 based on data classification metadata |
| Crypto usage provenance | First-party code vs. internal library vs. transitive OSS dependency |
| Multi-tenant / RBAC | Teams, roles, per-project access control |
| CBOM attestation | Sign + timestamp CBOM artifacts; publish to Sigstore/Rekor |
| Binary / JAR / wheel scanning | Scan compiled artefacts for crypto constants when source is unavailable |
| Runtime CBOM enrichment | Accept OpenTelemetry telemetry to enrich static CBOM with observed protocols and cipher suites |
| LLM-assisted remediation | For each finding, generate a concrete code change suggestion in the correct language |
| Custom source/sink config | For in-house crypto wrappers — define custom API endpoints as crypto sources/sinks |

---

## Feature Set 11: Source History & Infrastructure Intelligence

Features that extend the scanner beyond the current state of code into its history, its infrastructure layer, and its runtime negotiation behaviour.

| Feature | Description |
|---|---|
| Git history crypto archaeology | Scan entire git history (not just HEAD) — find when a weak algorithm was introduced, by whom, and whether a "fixed" hardcoded key was deleted vs. rotated |
| Secrets longevity tracker | Use `git blame` to calculate how long a hardcoded key or static IV has been in source control; age-weighted severity (1,000+ days = treat as compromised regardless of current usage) |
| IaC / cloud config crypto scanning | Scan Terraform, CloudFormation, Pulumi, Helm, Bicep, CDK for cloud-layer crypto misconfigurations: S3 encryption mode, RDS at-rest encryption toggle, KMS key rotation disabled, ACM/Key Vault/GCP KMS settings, Kubernetes TLS ingress, mTLS service mesh configs |
| Inter-service crypto consistency checker | In microservice portfolios, detect crypto mismatches between communicating services — TLS version incompatibilities, cipher suite conflicts, one-sided mTLS, services accepting TLS 1.0 because a downstream dependency requires it |
| Protocol negotiation analysis | Detect what cipher suites are *negotiable* not just configured — flag cipher lists containing both strong and weak entries (attacker forces weak path), `ssl_prefer_server_ciphers off`, SSLContext allowing client-side downgrade |
| Regulatory deadline burn-down dashboard | Live tracker: maps every quantum-vulnerable finding to its NIST IR 8547 deadline (2030/2035), estimates migration effort × instance count, projects completion date based on remediation velocity, exportable for board reporting |

---

## Feature Set 12: Developer Quality & Ownership Integration

Features that close the loop between crypto findings and the developers and teams responsible for them.

| Feature | Description |
|---|---|
| Crypto test coverage analyzer | Detect crypto operations with no corresponding tests for failure paths — wrong key rejection, IV randomness, authentication tag verification failure, PBKDF2 iteration count correctness |
| Crypto ownership heatmap | Correlate CODEOWNERS / git blame with crypto findings — per-team quantum-vulnerable finding count, per-team quantum readiness score, auto-assign Jira migration tickets to owning team |
| Crypto API surface coverage score | What percentage of the external API surface is protected by what crypto — maps HTTP/gRPC endpoints to their TLS config, identifies downgrade-permitted routes, flags weaker cipher suites on public-facing vs. internal routes |
| Database encryption audit | Scan ORM configs and SQL migration files for sensitive columns (email, SSN, credit card, password) lacking encryption, KDF usage for DB-level encryption keys, ORM field-level encryption library detection (Hibernate `@ColumnTransformer`, Django `encrypted-fields`, ActiveRecord `attr_encrypted`) with algorithm correctness check |
| PQC algorithm compatibility matrix | Per service/language: which PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) are available in the detected library stack today, platform support status, TLS 1.3 hybrid KEM availability, migration feasibility score (🟢 Ready / 🟡 Needs library upgrade / 🔴 No path yet) |
| Crypto migration project tracker | Auto-create migration tasks from quantum-vulnerable findings grouped by algorithm/service/team; track completion with burn-down chart; velocity-based ETA toward 2030/2035 deadlines; integrates with Jira, Linear, GitHub Issues |

---

## Feature Set 13: Extended Platform, Ecosystem & AI Features

Longer-horizon features requiring ML, ecosystem participation, or new scanning frontiers.

| Feature | Description |
|---|---|
| WASM / edge function crypto scanning | Scan WebAssembly bytecode deployed at edge (Cloudflare Workers, Fastly Compute@Edge, Deno Deploy) for crypto constant patterns — AES S-box, elliptic curve constants, RSA key material |
| AI-powered false positive triage | LLM classifies findings in context before surfacing — suppresses test fixture keys, non-security MD5 checksums, UI animation `Math.random()` — with human-readable rationale attached to each decision |
| Crypto anomaly detection | ML trained on historical CBOM snapshots per repo — detect unexpected algorithm appearance, service stopping TLS use, key size reduction, or crypto patterns matching known malware signatures (Cobalt Strike, Lazarus Group); supply chain compromise early-warning signal |
| CBOM marketplace / public hub | Community layer: publish CBOMs of OSS projects alongside releases, subscribe to CBOM updates for dependencies (like Dependabot for crypto posture), compare library choices against community crypto benchmarks |
| Supply chain CBOM federation | Publisher mode: auto-generate and sign CBOM on every release (GitHub Releases, npm, PyPI); consumers verify CBOM attestation before ingestion; downstream CBOM composition — consuming a library merges its CBOM into yours for full transitive crypto chain visibility |
| Mobile-specific deep scanning | Android `network_security_config.xml` cleartext/pinning bypass, iOS ATS `NSAllowsArbitraryLoads` exceptions, React Native native bridge vs. JS polyfill crypto, certificate pinning presence/absence, Play Store / App Store minimum TLS compliance checks |
