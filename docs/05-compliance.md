# Compliance Framework Mapping

> **Document version:** v1
> **Created:** 2026-03-15
> **Last updated:** 2026-03-15
> **Status:** Active

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-15 | Initial document | — |

---

## 1. Overview

CipherRadar maps every cryptographic finding to the relevant compliance frameworks automatically. This eliminates the manual effort of translating a raw crypto inventory into an audit-ready compliance gap report.

---

## 2. NIST SP 800-131A Rev. 3

**Who it applies to:** U.S. federal agencies and their contractors. Widely adopted as a de-facto standard globally.

**What it defines:** Algorithm transition guidance — which algorithms are Acceptable, Deprecated (transitional), or Disallowed.

| Status | Meaning | Action Required |
|---|---|---|
| Acceptable | Approved for current use | No action |
| Deprecated | Still usable but must be phased out — transition planned | Track + schedule migration |
| Disallowed | Must not be used | Immediate remediation |

**Key algorithm statuses (as of Rev. 3 draft):**

| Algorithm | Status | Notes |
|---|---|---|
| AES-128 / AES-192 / AES-256 | Acceptable | AES-256 preferred |
| SHA-256 / SHA-384 / SHA-512 | Acceptable | |
| SHA-3 family | Acceptable | |
| RSA-2048 (signing) | Deprecated → 2030 | Must migrate to PQC |
| RSA-3072+ (signing) | Deprecated → 2030 | Must migrate to PQC |
| ECC P-256 / P-384 | Deprecated → 2030 | Must migrate to PQC |
| DH-2048+ | Deprecated → 2030 | Must migrate to PQC |
| SHA-1 | Disallowed (signing/HMAC) | Remove immediately |
| MD5 | Disallowed (security) | Remove immediately |
| DES / 3DES | Disallowed | Remove immediately |
| RC4 | Disallowed | Remove immediately |
| RSA-1024 | Disallowed | Remove immediately |
| ML-KEM / ML-DSA / SLH-DSA | Acceptable (new) | NIST PQC finalized 2024 |

**CipherRadar mapping:** Every detected algorithm is tagged with its SP 800-131A status. A compliance report shows counts and locations for each status category.

---

## 3. FIPS 140-3

**Who it applies to:** U.S. federal procurement and any system processing sensitive government data. Also widely required in financial services, healthcare, and defence.

**What it defines:** Requirements for cryptographic module validation (CMVP). Approved algorithms, modes, key management requirements.

**Key FIPS 140-3 restrictions CipherRadar checks:**

| Check | Rule |
|---|---|
| Approved algorithms only | DES, RC4, MD5, SHA-1 (for signatures) are not approved |
| Approved modes | ECB mode is not FIPS-approved for confidentiality |
| Minimum key sizes | RSA ≥ 2048; AES ≥ 128 (256 preferred); EC ≥ 224 |
| Approved RNG | Must use an approved DRBG (Hash_DRBG, HMAC_DRBG, CTR_DRBG); not `Math.random()` or `rand()` |
| Key zeroization | Keys must be zeroized after use (static analysis can flag patterns of non-zeroization) |

**CipherRadar output:** FIPS gap report showing all non-compliant algorithm/mode/key-size combinations with file locations.

---

## 4. NSA CNSA 2.0

**Who it applies to:** All National Security Systems (NSS). Sets the bar for the most security-critical systems globally.

**Mandated algorithms:**

| Use Case | Required Algorithm | Standard |
|---|---|---|
| Key Encapsulation / Key Exchange | ML-KEM (Kyber) | FIPS 203 |
| Digital Signatures | ML-DSA (Dilithium) | FIPS 204 |
| Digital Signatures (hash-based) | SLH-DSA (SPHINCS+) | FIPS 205 |
| Symmetric Encryption | AES-256 | FIPS 197 |
| Hashing | SHA-384 or SHA-512 | FIPS 180-4 |

**Transition timeline CipherRadar tracks:**

| Milestone | Year | What Must Happen |
|---|---|---|
| New firmware/software signing | 2025 | Must support and prefer CNSA 2.0 algorithms |
| Network devices + OS | 2026–2027 | Must support PQC |
| All NSS | 2030 | Exclusively use CNSA 2.0 |
| Web/cloud communications | 2033 | Full PQC adoption |

CipherRadar flags: any use of RSA, ECC, or DH in signing or key exchange as a CNSA 2.0 violation, and shows the deadline by which it must be replaced.

---

## 5. PCI-DSS v4.0

**Who it applies to:** Any organisation that processes, stores, or transmits cardholder data.

**Relevant requirements:**

| Requirement | Description | CipherRadar Check |
|---|---|---|
| Req 4.2.1 | Strong cryptography for all data transmission over open networks | Detect weak TLS, no TLS, weak cipher suites |
| Req 3.5 | Protect stored account data using strong cryptography | Detect weak algorithms for data at rest |
| Req 3.6 | Key management: key generation, distribution, storage, retirement | Flag hardcoded keys, key material in source code |
| Req 3.7 | Key management policies and procedures | Detect expired/expiring certificates; key lifecycle state |
| Req 8.3 | Strong authentication | Detect weak password hashing (MD5, SHA-1 for passwords) |

---

## 6. EU Cyber Resilience Act (CRA)

**Effective:** December 2027 (compliance deadline for most manufacturers).

**CBOM relevance:**
- CRA requires SBOM in machine-readable format (CycloneDX 1.6+ or SPDX 3.0.1+)
- Requires ongoing cryptographic risk management over the product lifecycle
- Germany's BSI TR-03183-2 introduces cryptographic checksum requirements
- CBOM provides the structured artifact for demonstrating cryptographic risk management

**CipherRadar output for CRA:** CycloneDX 1.7 CBOM (machine-readable), compliance gap report, evidence of ongoing monitoring (scan history + trend data).

---

## 7. ISO 27001:2022

**Relevant control:** A.8.24 — Use of Cryptography

> "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented."

**CipherRadar supports A.8.24 by:**
- Providing a complete inventory of cryptographic controls in use
- Flagging deviations from the organisation's cryptographic policy
- Tracking key material lifecycle (expiry, hardcoded keys, state)
- Generating audit evidence for certification

---

## 8. NIST Cybersecurity Framework (CSF) 2.0

| CSF Function | Relevant Subcategory | CipherRadar Role |
|---|---|---|
| **Identify (ID)** | ID.AM-2: Software assets inventoried | CBOM is the cryptographic layer of the software inventory |
| **Identify (ID)** | ID.RA-1: Asset vulnerabilities identified | Quantum-vulnerable algorithm inventory |
| **Protect (PR)** | PR.DS-1: Data-at-rest protected | Detect weak algorithms for stored data |
| **Protect (PR)** | PR.DS-2: Data-in-transit protected | Detect weak TLS, plaintext protocols |
| **Protect (PR)** | PR.PS-3: Configuration managed | Config file scanning for crypto misconfig |

---

## 9. Custom Policy Engine

Beyond pre-built frameworks, organisations can define custom cryptographic policies in YAML. See [Features — Feature Set 6](04-features.md#feature-set-6-policy-engine) for the full policy syntax.

**Use cases for custom policies:**
- "Our organisation requires AES-256 minimum, not AES-128"
- "We have approved only P-384 and Curve25519 for ECDH — not P-256"
- "All new code must use TLS 1.3 only"
- "JWT must use RS256 or ES256 only — no HS256 in production services"
- "PBKDF2 must use at least 600,000 iterations with SHA-256"

---

## 10. Compliance Score

Every repository and the entire portfolio receives a compliance score per framework:

```
NIST SP 800-131A:  82/100  [14 deprecated, 2 disallowed]
FIPS 140-3:        91/100  [3 non-compliant algorithm/mode combinations]
PCI-DSS v4.0:      76/100  [hardcoded key material in 2 services]
NSA CNSA 2.0:      41/100  [RSA/ECC used in 23 services — PQC migration pending]
Custom Policy:     95/100  [1 WARN: AES-128 in legacy service]
```

Scores trend over time and are visible in the compliance dashboard.
