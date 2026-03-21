# ADR-026: Binary Scanning Architecture — Hybrid (Go Byte-Patterns + YARA-X)

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

CipherRadar's detection engine (ADR-004) operates on source code. Phase 4 extends scanning to compiled binaries — native executables, shared libraries, JAR files, and Python wheels — where cryptographic algorithms are embedded as machine code or byte sequences rather than readable API calls.

Binary scanning requires a fundamentally different detection approach: cryptographic algorithms leave identifiable byte patterns (S-boxes, round constants, magic numbers) in compiled output regardless of the source language or compiler used. The scanner must detect these patterns reliably while maintaining the two-tier distribution model (lightweight vs full) established in ADR-010.

Additionally, some binary formats (JAR, Python wheels) are simply archives containing source or bytecode that can be extracted and scanned with existing source-level scanners.

---

## Decision

### Two-tier binary scanning aligned with distribution model

**`cradar` (lightweight binary): Pure Go byte-pattern matcher**

A Go-native pattern matching engine with YAML-defined detection rules embedded via `//go:embed` (consistent with ADR-010 shared asset embedding). Detects well-known cryptographic constants:

| Pattern | Signature | Size |
|---|---|---|
| AES S-box | Forward substitution table | 256 bytes |
| SHA-256 round constants | K[0..63] | 64 × 4 bytes |
| DES S-boxes | 8 substitution boxes | 8 × 64 bytes |
| RSA public key structures | ASN.1 DER-encoded PKCS#1/PKCS#8 headers | Variable |
| Algorithm OIDs | Known OID byte sequences for RSA, ECDSA, Ed25519, AES-CBC, etc. | Variable |

Expected accuracy: ~70% of cryptographic assets in compiled binaries.

**`cradar-full`: YARA-X binary bundled**

The full distribution bundles the YARA-X binary (Rust rewrite of YARA, Apache 2.0). Scanning uses:
- Full `findcrypt-yara` ruleset (community-maintained, covers 200+ algorithm signatures)
- Custom CipherRadar YARA rules for patterns not in findcrypt (PQC candidates, hybrid key exchanges)

Expected accuracy: ~90%+ of cryptographic assets in compiled binaries.

**Graceful degradation:** If YARA-X is not available at runtime, `cradar` falls back to the Go byte-pattern matcher and prints: `Binary Pass 2 skipped — YARA-X not found; run 'cradar install-tools' or use cradar-full`. This follows the same pattern as Pass 2/3 degradation in ADR-010.

### Archive-based binary formats

These formats contain extractable source or bytecode — they are unpacked and scanned with existing language scanners:

| Format | Strategy |
|---|---|
| JAR files | Decompile via CFR (Java decompiler, Apache 2.0) as subprocess → scan decompiled `.java` with existing Java scanner |
| Python wheels (.whl) | Extract `.py` files from zip archive → scan with existing Python scanner |

CFR follows the same tool distribution model: bundled in `cradar-full`, downloadable via `cradar install-tools`.

---

## Options Considered

### Option A: YARA-only (rejected)
YARA-X via CGo bindings would give the best accuracy in a single binary. Rejected because CGo breaks the lightweight binary's portability guarantees and adds cross-compilation complexity. The YARA C library is ~2 MB but pulls in OpenSSL as a transitive dependency on some platforms.

### Option B: Disassembly-based analysis (rejected)
Full disassembly (Capstone/Ghidra headless) followed by control-flow analysis to identify crypto implementations. Rejected as overkill — byte-pattern matching achieves sufficient accuracy for CBOM generation without the complexity and performance cost of disassembly. Disassembly is appropriate for vulnerability research, not asset inventory.

### Option C: Go-only with extended patterns (rejected)
Expanding the Go byte-pattern matcher to cover all known signatures without YARA-X. Rejected because maintaining a custom pattern engine at the scale of findcrypt-yara (200+ rules) is significant ongoing effort, and YARA's pattern matching language is purpose-built for this problem.

---

## Consequences

- **Positive:** Lightweight binary gains binary scanning capability (~70% accuracy) with zero external dependencies
- **Positive:** Full binary achieves ~90%+ accuracy by leveraging the mature YARA ecosystem
- **Positive:** JAR and wheel scanning reuses existing source-level scanners — no new detection logic needed
- **Positive:** Graceful degradation preserves the user experience established in ADR-010
- **Negative:** Two detection paths means two sets of detection rules to maintain (Go YAML + YARA rules)
- **Negative:** CFR decompilation adds JVM as an indirect dependency for JAR scanning
- **Negative:** YARA-X is a Rust binary (~15 MB) — increases `cradar-full` archive size

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| ADR-010 | `cradar-full` now bundles 3 tools (OpenGrep, Joern, YARA-X); size target updated to ~300 MB |
| `docs/03-detection-engine.md` | New section: Binary scanning passes (Go byte-patterns + YARA-X) |
| `docs/07-tech-stack.md` | YARA-X and CFR added to tech stack |
| `cli/internal/tools/installer.go` | `InstallYARAX()` function added |
| `scanner/rules/` | New `binary/` subdirectory for Go byte-pattern YAML rules and custom YARA rules |
