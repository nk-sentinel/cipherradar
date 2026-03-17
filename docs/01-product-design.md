# Product Design

## 1. Vision Statement

> A source-code-first CBOM platform that discovers, inventories, classifies, and tracks every cryptographic asset across a software portfolio — continuously, across all languages — and translates findings into actionable compliance, quantum-readiness, and remediation guidance.

---

## 2. The Problem

### 2.1 The Quantum Threat Creates an Urgent Discovery Gap

Cryptographically-relevant quantum computers (CRQCs) will render RSA, ECC, DH, and DSA insecure. NIST IR 8547 defines the transition timeline:

| Milestone | Year |
|---|---|
| RSA-2048, ECC P-256, DH-2048 **deprecated** | 2030 |
| All classical public-key algorithms **disallowed** | 2035 |

The migration to post-quantum cryptography is the largest cryptographic transition in computing history. **You cannot migrate what you cannot find.** Most organisations have no structured inventory of where RSA, ECC, or DH are used in their codebases.

### 2.2 Compliance Pressure Is Accelerating

| Framework | Cryptographic Requirement |
|---|---|
| NIST SP 800-131A Rev. 3 | Defines Acceptable / Deprecated / Disallowed algorithms with timelines |
| FIPS 140-3 | Mandates CMVP-validated modules; specific algorithm/mode restrictions |
| NSA CNSA 2.0 | Mandates PQC for all National Security Systems by 2030–2033 |
| PCI-DSS v4.0 | Strong cryptography required; key inventory mandated |
| EU Cyber Resilience Act (Dec 2027) | SBOM + cryptographic risk management over product lifecycle |
| Executive Order 14028 + EO 14144 | Software supply chain transparency; SBOM/CBOM for federal suppliers |

### 2.3 Existing Tools Are Insufficient

| Tool | Gap |
|---|---|
| **sonar-cryptography / CBOMkit** | Java and Python only; produces raw JSON with no guidance |
| **cryptobom-forge** | Requires CodeQL setup; wraps an external tool |
| **GitHub CodeQL PQC queries** | Requires CodeQL infrastructure; no dashboard or workflow |
| **IBM Quantum Safe Explorer** | Commercial, not accessible to most teams |
| **SonarQube built-in rules** | Not CBOM-aware; no CycloneDX output; no quantum context |

No existing open tool provides: multi-language coverage, compliance mapping, quantum-readiness scoring, a policy engine, and developer workflow integration in a single product.

---

## 3. Pain Points by Persona

### CISO / Security Leadership
- "We don't know what cryptographic algorithms are running across our systems."
- "We can't pass a FIPS 140-3 / CNSA 2.0 audit without a crypto inventory."
- "We have no idea how exposed we are to the quantum threat."

### Security Architect / Platform Engineering
- "We need to migrate to PQC but don't know where RSA or ECC lives in the codebase."
- "Existing CBOM tools only support Java and Python — we have Go, Kotlin, C#, Rust, Swift."
- "We need to enforce cryptographic standards across 50+ microservices."

### AppSec / DevSecOps Team
- "We can't remediate crypto misuse (static IVs, ECB mode, hardcoded keys) we haven't found."
- "We need CI/CD gates that fail builds when prohibited algorithms are introduced."
- "We need SARIF output so findings surface in GitHub Security tab and PR reviews."

### Compliance / GRC Team
- "We need audit evidence of cryptographic inventory for PCI-DSS and FIPS compliance."
- "We need a gap report against NIST SP 800-131A for our annual assessment."
- "We need to track certificate expiry across the portfolio."

### Developer
- "I don't know if the crypto I'm writing is correct or compliant."
- "I want to see crypto findings in my IDE before code review, not after."

---

## 4. Product Goals

### Primary Goals
1. **Comprehensive discovery** — find every cryptographic asset in source code, config, and containers across 12+ languages
2. **Structured output** — emit valid CycloneDX 1.7 CBOM for every scan
3. **Quantum classification** — automatically tag every finding with quantum vulnerability status and NIST PQC security level
4. **Actionable guidance** — translate raw findings into compliance gaps, risk scores, and concrete remediation steps
5. **Developer integration** — surface findings in the developer workflow (IDE, PR, CI/CD) not just in security dashboards

### Non-Goals (Phase 1)
- Dynamic / runtime analysis (addressed via enrichment hook in Phase 4)
- Binary-only scanning without source (addressed in Phase 4)
- DAST / penetration testing capabilities
- Key management system (KMS) functionality

---

## 5. Success Metrics

| Metric | Target |
|---|---|
| Languages supported | 12+ by Phase 4 |
| False positive rate | < 5% for High/Critical findings |
| Scan time for 100k LOC repo | < 5 minutes |
| CycloneDX spec compliance | 100% valid against CycloneDX 1.7 schema |
| CI/CD integration coverage | GitHub Actions, GitLab CI, Jenkins |
| Compliance frameworks mapped | NIST SP 800-131A, FIPS 140-3, PCI-DSS v4.0, NSA CNSA 2.0, ISO 27001, EU CRA |

---

## 6. Design Principles

1. **Accuracy over coverage** — a finding must be trustworthy. Low-confidence findings are labelled, not suppressed.
2. **Context, not just inventory** — reporting "AES is used" is not enough. Report AES-128-CBC-PKCS7 at file:line with quantum status and compliance mapping.
3. **Actionable, always** — every finding links to remediation guidance, relevant standards, and a suggested fix.
4. **Developer-first** — findings must reach developers where they work (IDE, PR, CLI) not just in a security portal.
5. **Open standards** — CycloneDX 1.7 output, SARIF, SPDX. No proprietary lock-in.
6. **Cryptographic agility** — the product should model and encourage cryptographic agility (the ability to swap algorithms without system redesign).
7. **Continuous, not point-in-time** — CBOM should be regenerated on every build. Drift detection and trend analysis are core, not add-ons.
