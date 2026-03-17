# cbomExtractor

> A source-code-first Cryptography Bill of Materials (CBOM) platform that discovers, inventories, classifies, and tracks every cryptographic asset across a software portfolio — continuously, across all languages — and translates findings into actionable compliance, quantum-readiness, and remediation guidance.

---

## What Is a CBOM?

A **Cryptography Bill of Materials (CBOM)** is a structured inventory of all cryptographic assets used within a software system. It is the cryptographic counterpart to an SBOM (Software Bill of Materials), standardised in **CycloneDX v1.6** (April 2024) and expanded in **CycloneDX v1.7** (October 2025 / ECMA-424 2nd Edition).

A CBOM inventories:
- **Algorithms** — AES-256-GCM, RSA-2048, SHA-256, ML-KEM, etc.
- **Protocols** — TLS versions, cipher suites, SSH, JWT/JOSE, IPsec
- **Certificates** — X.509 certs with validity, signature algorithm, key size
- **Related Cryptographic Material** — keys, IVs, nonces, salts, hardcoded secrets, PRNG usage

---

## Why This Matters

| Driver | Detail |
|---|---|
| **Post-Quantum Migration** | RSA, ECC, DH, DSA will be broken by cryptographically-relevant quantum computers. NIST IR 8547 deprecates them by 2030 and disallows them by 2035. You cannot migrate what you cannot find. |
| **Compliance** | FIPS 140-3, NIST SP 800-131A Rev.3, NSA CNSA 2.0, PCI-DSS v4.0, EU Cyber Resilience Act all require cryptographic inventories. |
| **Supply Chain Security** | Executive Order 14028 + EO 14144 mandate software supply chain transparency. CBOM extends SBOM to the cryptographic layer. |
| **Crypto Misuse** | Static IVs, hardcoded keys, ECB mode, PKCS1v15 padding, MD5 passwords — common vulnerabilities invisible without dedicated crypto scanning. |

---

## Documentation Index

| Document | Description | Version |
|---|---|---|
| [Product Design](docs/01-product-design.md) | Vision, problem statement, user personas, product goals | v1 |
| [Architecture](docs/02-architecture.md) | System architecture, component diagram, deployment models | v1 |
| [Detection Engine](docs/03-detection-engine.md) | How scanning works, per-language strategies, confidence scoring | **v2** |
| [Features](docs/04-features.md) | Complete feature breakdown across all 10 feature sets | v1 |
| [Compliance Mapping](docs/05-compliance.md) | NIST, FIPS, PCI-DSS, CNSA 2.0, CRA framework details | v1 |
| [Data Model](docs/06-data-model.md) | Core entities, CycloneDX schema fields, relationships | v1 |
| [Tech Stack](docs/07-tech-stack.md) | Technology decisions and rationale | **v2** |
| [Roadmap](docs/08-roadmap.md) | Phased delivery plan across 4 phases | **v2** |

## Decision Log & Architecture Decision Records

| Document | Description |
|---|---|
| [Decision Log](docs/DECISION-LOG.md) | **Master index** — all decisions, timeline, changes, open questions, lessons learned |
| [ADR-001](docs/decisions/ADR-001-output-format.md) | Output Format — CycloneDX 1.7 |
| [ADR-002](docs/decisions/ADR-002-parsing-backbone.md) | Parsing Backbone — tree-sitter |
| [ADR-003](docs/decisions/ADR-003-codeql-independence.md) | No CodeQL dependency; no build required |
| [ADR-004](docs/decisions/ADR-004-taint-engine-revision.md) | **Taint engine revised** — custom build replaced with Joern + Semgrep |
| [ADR-005](docs/decisions/ADR-005-cli-language-and-deployment.md) | CLI in Go; Backend in Python/FastAPI |

---

## Quick Summary: What Gets Built

```
Source Code / Containers / Config Files
            │
            ▼
    cbomExtractor Scanner
    (12+ languages, AST + Taint + Regex)
            │
            ▼
    CycloneDX 1.7 CBOM
    (algorithms, protocols, certs, key material)
            │
            ├── Risk & Quantum Readiness Scoring
            ├── Cryptographic Misuse Detection
            ├── Compliance Mapping (NIST / FIPS / PCI / CNSA 2.0)
            ├── Policy Engine (YAML-based, CI/CD gate)
            ├── Dashboard & Visualization
            └── Reports (PDF / SARIF / HTML / CSV)
```

---

## What Makes cbomExtractor Different

| Gap in Existing Tools | cbomExtractor Solution |
|---|---|
| sonar-cryptography supports Java + Python only | 12+ languages from day-one roadmap |
| CBOMkit produces raw JSON with no guidance | Compliance mapping, risk scoring, remediation, dashboard |
| No quantum migration workflow in any OSS tool | PQC readiness reports, NIST IR 8547 deadline tracking, migration Kanban |
| No policy-as-code for cryptography | YAML policy engine with CI/CD build gates |
| No SBOM ↔ CBOM correlation | When a crypto library CVE drops, instantly see your exposure |
| No certificate expiry tracking | Certificate calendar + automated expiry alerts |
| Static analysis only | Runtime telemetry enrichment hook for observed cipher suites |
| No developer-facing tooling | IDE plugins, PR comments, pre-commit hooks |

---

## Standards and References

- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/)
- [OWASP Authoritative Guide to CBOM (PDF)](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf)
- [NIST IR 8547 — Transition to Post-Quantum Cryptography](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [NIST SP 800-131A Rev. 3 Draft](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-3/draft)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)
- [FIPS 203 / ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 / ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 / SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [CBOMkit (PQCA / Linux Foundation)](https://github.com/cbomkit/cbomkit)
- [IBM Cryptoscope Research Paper — arXiv:2503.19531](https://arxiv.org/abs/2503.19531)
