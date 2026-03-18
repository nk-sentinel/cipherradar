# ADR-001: Output Format — CycloneDX 1.7 CBOM

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-15 |
| **Last updated** | 2026-03-18 |
| **Deciders** | Architecture session |

---

## Context

A CBOM scanner must produce output in a format that:
- Is machine-readable and interoperable with downstream tooling (Dependency-Track, SBOMit, etc.)
- Is standardised enough for compliance auditors to accept as evidence
- Supports all four cryptographic asset types: algorithms, protocols, certificates, related crypto material
- Carries quantum-readiness metadata (NIST PQC security level)
- Can be embedded within or linked to an SBOM

Multiple formats were considered:
- Custom JSON schema (proprietary)
- SPDX 3.0 with crypto annotations
- CycloneDX 1.6 CBOM
- CycloneDX 1.7 CBOM

## Decision

**CycloneDX 1.7 CBOM JSON/XML** as the primary output format, with SARIF 2.1 and CSV as secondary export formats.

## Rationale

- CycloneDX 1.7 is the only open standard with a formally specified `cryptoProperties` schema covering all four asset types
- Ratified as ECMA-424 2nd Edition (December 2025) — has formal international standards body backing
- `nistQuantumSecurityLevel` field is native to the schema — no custom extensions needed
- Official CycloneDX libraries exist for Go, Python, Java, Node.js — reduces implementation risk
- Dependency-Track and other portfolio tools already consume CycloneDX natively
- SPDX 3.0 has crypto annotations but they are less mature and less tooling support exists
- Proprietary schema would prevent interoperability with existing ecosystem tools

## Consequences

- Positive: Interoperable with all CycloneDX-compatible tools out of the box
- Positive: Schema validation available via official JSON Schema — can validate output correctness
- Positive: Future spec changes handled by the CycloneDX library, not our code
- Negative: Schema evolution (1.7 → 1.8+) requires library updates
- Negative: CycloneDX is more complex than a custom schema for simple use cases

## Implementation Note — Go Library Gap (added 2026-03-18)

A feasibility study (triggered by a stack audit) identified that `cyclonedx-go` v0.10.0 supports CycloneDX 1.0–1.6 only. CycloneDX 1.7 support (issue #247) has an open PR (#257, opened Feb 2026) that remains unmerged with no timeline.

**Approach for Phase 1 CLI (Go):**

Use `cyclonedx-go` for the document envelope (metadata, component structure, dependencies) and build a small internal package `cli/internal/cyclonedx17/` covering only the `cryptoProperties` additions needed for CBOM:

| Struct | Fields |
|---|---|
| `AlgorithmProperties` | primitive, algorithmFamily, parameterSetIdentifier, executionEnvironment, implementationPlatform, certificationLevels, mode, padding, cryptoFunctions, classicalSecurityLevel, nistQuantumSecurityLevel |
| `CertificateProperties` | subjectName, issuerName, notValidBefore, notValidAfter, signatureAlgorithmRef, subjectPublicKeyRef, certificateFormat, certificateExtension |
| `ProtocolProperties` | type, version, cipherSuites, ikev2TransformTypes, cryptoRefs |
| `RelatedCryptoMaterialProperties` | type, id, state, algorithmRef, securedBy, size |
| Supporting enums | primitive, algorithmFamily (96 values), mode, padding, cryptoFunctions, nistQuantumSecurityLevel, quantumStatus |

Estimated scope: ~420 lines of Go. Python library (`cyclonedx-python-lib` v11.7.0) provides a working reference for struct design.

**Migration path:** Monitor `cyclonedx-go` PR #257. When it merges, delete `cli/internal/cyclonedx17/` and migrate to the official library. The internal package is designed as a drop-in to make this migration straightforward.

**Backend (Python):** `cyclonedx-python-lib` v11.7.0 supports 1.7 — no gap, no workaround needed.

## Alternatives Considered and Rejected

| Option | Reason Rejected |
|---|---|
| Custom JSON | No interoperability; reinventing the wheel; no compliance body would accept it |
| SPDX 3.0 | Crypto annotations less mature; fewer tools consume it for CBOM specifically |
| CycloneDX 1.6 | Missing CycloneDX 1.7 enhancements: standardised `algorithmFamily`, expanded PQC support, provenance fields |

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/07-tech-stack.md` | CycloneDX Go library and cyclonedx-python-library listed as dependencies |
| `docs/04-features.md` | Feature Set 2 (CBOM Management) and reporting formats derived from this decision |
| `docs/08-roadmap.md` | Phase 1 success criteria: CycloneDX 1.7 schema validation passes 100% |
