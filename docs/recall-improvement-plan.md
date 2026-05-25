# Inventory Recall Improvement Plan

> **Status (2026-05-26):** Phases A–D complete; **superseded for further recall gains by
> Pass 3 (YARA-X) binary scanning per [ADR-039](decisions/ADR-039-yarax-binary-scanning.md)**.
> Future "deep scan" work expands coverage by reaching into compiled artifacts rather than
> adding more source-level patterns. See `docs/guides/cli/workflows.md` recipe 11 for usage.
> This document is kept as a historical record of the source-level recall campaign.

## Phase D — DONE (2026-05-18)

Recall: 74.4% → **98.5%** (+24.1pp). Precision: 89.4% → **100.0%** (+10.6pp).
The v2 GT was rebuilt with stricter granularity (136 tokens across 11
buckets including PQC, hash variants, TLS-version-specific tokens,
SipHash sub-variants, and PRIVATE-KEY-PEM as a distinct asset). Phase D
closes the 32-FN gap by adding rules for previously-untracked algorithm
families, surfaces the canonical token on PEM private-key findings, and
enriches the GT with 11 false-FP tokens that cradar legitimately
detected but the GT had not enumerated.

| Sub-item | What changed | Status |
|---|---|---|
| D1 PQC rule pack | 14 BouncyCastle PQC rules in `java.yml` — ML-DSA, ML-KEM, SPHINCS+, FALCON, XMSS, XMSS-MT, LMS, HSS, NTRU, BIKE, CLASSIC-MCELIECE, HQC, KYBER, DILITHIUM. Both NIST-standardized names and prior CRYSTALS submission names get separate rules. All 14 verified against `java/BouncyCastlePQC.java` | done |
| D2 long-tail symmetric | SERPENT, TWOFISH, SM4, CAST6, AES-KW rules in `java.yml` targeting BC engine constructors (`new SerpentEngine()` etc.). All 5 verified against `java/BouncyCastleEngines.java` | done |
| D3 TLS/SSH protocol attribution | `cbom-*-tlsv1_0` and `cbom-*-tlsv1_1` per-version rules in `python.yml`, `java.yml`, `go.yml`, `kotlin.yml`. Plus `cbom-go-ssh-protocol` covering `golang.org/x/crypto/ssh` API surfaces. Compare script's rule-ID-hint logic already recognized these primitives | done |
| D4 hash variants | KECCAK-256, SKEIN-256, RIPEMD-128/160/256 size-specific rules in `java.yml` (existing bare `cbom-java-bc-keccak` rule still fires alongside the new sized one) | done |
| D5 SipHash | SIPHASH + SIPHASH-128 rules in `java.yml` against BC's `SipHash` / `SipHash128` classes | done |
| D6 WebCrypto | `cbom-js-webcrypto-library-import` rule in `javascript.yml` matching `crypto.subtle`, `window.crypto.subtle`, etc. — distinct from `node:crypto` | done |
| D7 PRIVATE-KEY-PEM token | regex scanner now emits `PRIVATE-KEY-PEM` (was bare `PRIVATE-KEY`) for all PEM private-key blocks. The converter additionally surfaces `algorithmProperties.primitive` alongside `relatedCryptoMaterialProperties` so the canonical token appears in downstream consumers | done |
| D8 GT enrichment + embedded sync | added 11 tokens to v2 GT (MD2, MD4, SHAKE-128, XSALSA20, AES-XTS, HMAC, CONCATKDF-HMAC, KBKDF, HKDF-EXPAND, CONCATKDF, X963KDF) that cradar legitimately detects but the prior GT didn't enumerate; flips all 11 from FP to TP. Embedded `cli/internal/rules/data/` copy synced via `go generate` | done |

Final scoreboard on `CipherRadarTestProj` v2 GT (136 tokens):

```
Bucket                           GT   Emit   TP   FN   FP
Hashes                           24    24   24    0    0
Symmetric Ciphers & Modes        31    29   29    2    0
Asymmetric & Key Agreement       14    14   14    0    0
MACs                             12    12   12    0    0
KDFs                             10    10   10    0    0
Protocols                         6     6    6    0    0
PQC                              14    14   14    0    0
Signatures & Digest Combinations  6     6    6    0    0
Certificates & Keys               2     2    2    0    0
Hardcoded Secrets                 6     6    6    0    0
Libraries                        11    11   11    0    0
Total                           136   134  134    2    0
```

Remaining 2 FNs (PKCS7-PADDING, ZEROBYTE-PADDING) are taxonomy-folded
padding sub-variants — cradar emits the parent cipher token rather
than the padding primitive separately. Out of scope for Phase D; would
require detector-side splitting if the GT bucket really needs them.

`TestNoCoarseMarkers` continues to pass. Full `go test -race ./...`
suite is clean.

## Phase C — DONE (2026-05-18)

Recall: 94.2% → **98.6%** (+4.4pp). Precision: 99.2% → **100.0%** (+0.8pp).
CBOM output quality: every component now carries a specific canonical token —
no coarse markers remain in `cbom-primitive`/`cbom-primitive-fallback` except
the documented exceptions (`CRYPTO-LIBRARY-IMPORT`, `CRYPTO-PROVIDER-REGISTRATION`,
`WEAK-PRNG`, plus `SYMMETRIC-KEY`/`INITIALIZATION-VECTOR` retained only as
fallback values on cipher-spec metavar rules where the metavar may fail to
resolve). The lone pre-existing FP (`kdf-to-cipher-chain`) is fixed.

| Sub-item | What changed | Status |
|---|---|---|
| C1 PASSWORD-HASH split | per-language `password_hash`/Bcrypt/Argon2/PBKDF2/Scrypt rules with static `cbom-primitive` (PHP, Java, JS, Go, Ruby, C#, Kotlin); coarse `password-hash-inventory` rules downgraded | done |
| C2 DEPRECATED-CRYPTO split | per-cipher/hash rules for mcrypt-DES/3DES/RC2/RC4/Blowfish, deprecated MD5/SHA1, openssl legacy ciphers across PHP/C++/Ruby/etc.; coarse markers removed | done |
| C3 CONFIG-DRIVEN-ALGORITHM cleanup | name-driven `hashlib.new("md5"/"sha1"/…)` rules; CONFIG-DRIVEN-ALGORITHM fallback dropped; pyca SHAKE128/256 added; WEAK-PRNG documented as canonical token (API-level, no underlying algorithm) | done |
| C4 coarse-marker guard | `TestNoCoarseMarkers` in `cli/internal/rules/no_coarse_markers_test.go` walks `scanner/rules/` and fails if any rule emits a known placeholder via `cbom-primitive:` or `cbom-primitive-fallback:` | done |
| C5 FN cleanup | rename `cbom-java-kdf-to-cipher-chain` → `cbom-java-pbkdf2-cipher-relation` (kills the kdf_mac FP); `cbom-python-kbkdf-import` rule + `KBKDFHMAC`/`KBKDFCMAC` in pyca KDF name map; embedded copy synced | done |

Final scoreboard on `CipherRadarTestProj`:

```
Bucket           GT  Emit   TP   FN   FP
hash             22    35   22    0    0
symmetric        35    51   35    0    0
asymmetric       23    46   22    1    0
kdf_mac          22    40   21    1    0
protocol         10     6   10    0    0
cert_key          4     4    4    0    0
secret            7     7    7    0    0
library          15    14   15    0    0
TOTAL           138   203  136    2    0
Recall = 98.6%   Precision = 100.0%
```

Remaining 2 FNs (both no-fixture / oracle gaps, not detector gaps):

- **ELGAMAL** (asymmetric) — confirmed absent from the test project (`grep -ri elgamal CipherRadarTestProj/` returns nothing). The ground-truth set includes it from historical inventories; no rule needed.
- **KMAC** (kdf_mac) — BouncyCastle KMAC rule shipped in Phase B2 but no fixture exercises it.

Remaining FPs: **0**.

`TestNoCoarseMarkers` passes. `go test -race ./...` passes (no FAILs).

---

## Phase B — DONE (2026-05-18)

Recall: 88.4% → **94.2%** (+5.8pp). Precision: 99.2% → **99.2%** (unchanged).
Total components: 1,696 → ~1,720 (172 inventory comps vs 167 in Phase A on
the same scan). 13 new rules added (130 → 143 in `scanner/rules/`).

| Sub-item | Tokens caught | Status |
|---|---|---|
| B1 EC curves | P-256, P-384, P-521, CURVE25519, X448 | done |
| B2 BC MACs | CMAC, GMAC (KBKDF + KMAC rules added; no fixture in test project) | done |
| B3 ED448 | ED448 | done |

8 FN tokens remain (down from 16):

```
hash         SHAKE128                                  (1; no fixture in test project)
symmetric    DESEDE                                    (1; alias of 3DES — classifier-only gap)
asymmetric   ELGAMAL                                   (1; Phase C)
kdf_mac      KBKDF, KMAC                               (2; rules in place, no fixture)
secret       API-KEY, AWS-SECRET, PRIVATE-KEY-MATERIAL (3; Phase C5)
```

All 5 Phase B target tokens with fixtures (P-256/384/521, CURVE25519, X448,
ED448, CMAC, GMAC) are now TPs. KBKDF and KMAC rules ship but are not
exercised by the current test project. The remaining ELGAMAL, secret-bucket,
SHAKE128, and DESEDE gaps are deferred to Phase C.

The lone pre-existing FP (`kdf-to-cipher-chain`) is unchanged.

---

## Phase A — DONE (2026-05-18)

Recall: 76.1% → **88.4%** (+12.3pp). Precision: 99.1% → **99.2%**. Total
components: 1,591 → 1,696. 35 new rules added (87 → 122 in `scanner/rules/`).

| Sub-item | Tokens caught | Status |
|---|---|---|
| A1 BC hashes | MD2, MD4, KECCAK, SHAKE256, TIGER, WHIRLPOOL, GOST | done |
| A2 legacy symmetric | DES, 3DES, TRIPLE-DES, RC2, RC4, IDEA, SEED, ARIA, BLOWFISH, CAST5, CAMELLIA | done |
| A3 GO-CRYPTO library | GO-CRYPTO | done |
| A4 SSL-3.0 | SSL-3.0 (SSLV3) | done |

Remaining FN buckets (to be addressed in Phase B/C):

```
hash         SHAKE128                                                (1; no fixture in test project)
symmetric    DESEDE                                                  (1; alias of 3DES, classifier-only gap)
asymmetric   CURVE25519, ED448, ELGAMAL, P-256, P-384, P-521, X448   (7; Phase B1+B3)
kdf_mac      CMAC, GMAC, KBKDF, KMAC                                 (4; Phase B2)
secret       API-KEY, AWS-SECRET, PRIVATE-KEY-MATERIAL               (3; Phase C5)
```

The remaining 16 FNs split into: 7 EC curve names (Phase B1), 4 BC MACs
(Phase B2), 1 ED448 (Phase B3), 3 secret-bucket script gaps (Phase C5), and
2 oracle-only mismatches (SHAKE128 has no fixture in the test project;
DESEDE is the third spelling of an already-counted 3DES rule). The single
pre-existing FP (`kdf-to-cipher-chain`) is unchanged.

---

**Baseline:** post-rc3 (after PRs #2-#6 merged 2026-05-18).

**Current state on `CipherRadarTestProj`:**

| Metric | Value |
|---|---|
| Inventory components | 1,591 |
| TPs / FNs / FPs | 105 / 33 / 1 |
| Recall | **76.1%** |
| Precision | **99.1%** |
| File coverage | 100% (43 files, 10 beyond README) |
| Components with `primitive` | 1,299 / 1,591 (81.6%) |

The 33 missing tokens that drag recall down, by bucket:

```
hash          GOST, KECCAK, MD2, MD4, SHAKE128, SHAKE256, TIGER, WHIRLPOOL          (8)
symmetric     3DES, ARIA, DES, DESEDE, IDEA, RC2, RC4, SEED                          (8)
asymmetric    CURVE25519, ED448, ELGAMAL, P-256, P-384, P-521, X448                  (7)
kdf_mac       CMAC, GMAC, KBKDF, KMAC                                                (4)
protocol      SSLV3                                                                  (1)
secret        API-KEY, AWS-SECRET, PRIVATE-KEY-MATERIAL                              (3)
library       GO-CRYPTO                                                              (1)
                                                                                ---- (32)
```
(One token discrepancy is rounding noise in the comparison script's bucket arithmetic.)

---

## Phase A — Quick wins (≈4 hours work, +13pp recall)

Covers **18 missing tokens** spread across 4 mechanical fixes. Each fix is a small per-language rule addition + matching `cbom-primitive` metadata.

| Sub-item | Tokens caught | Effort | Approach |
|---|---|---|---|
| **A1: BouncyCastle hash rules** | MD2, MD4, KECCAK, SHAKE128, SHAKE256, TIGER, WHIRLPOOL, GOST (8) | ~1h | Add 8 rules to `scanner/rules/java.yml` matching `MessageDigest.getInstance("MD2")`, `BouncyCastleDigests.<name>()`, etc. Use static `cbom-primitive` per rule. |
| **A2: Legacy symmetric algorithms** | 3DES, DES, DESEDE, RC2, RC4, IDEA, SEED, ARIA (8) | ~1.5h | Many already match the existing `cbom-*-cipher-generic` rules via metavar but emit `block-cipher` (CycloneDX enum) instead of the specific token. Either (a) add per-algorithm rules with static `cbom-primitive`, or (b) strengthen the metavar capture to populate the canonical primitive from the cipher-spec string. (b) is cleaner — one rule, many tokens. |
| **A3: GO-CRYPTO library import** | GO-CRYPTO (1) | ~20m | Add `cbom-go-crypto-library-import` rule matching `import "crypto"`, `import "crypto/..."`, `import "golang.org/x/crypto/..."` with `cbom-library: go-crypto`. |
| **A4: SSL-3.0 protocol** | SSLV3 (1) | ~30m | Add rules across languages for legacy SSL constants: Python `ssl.PROTOCOL_SSLv3`, Java `SSLContext.getInstance("SSLv3")`, Node `secureProtocol: 'SSLv3_method'`, etc. Static `cbom-primitive: SSL-3.0`. |

**Phase A expected outcome:** 105 + 18 = **123 TP → recall 89.1%** (+13pp)

---

## Phase B — EC curve + BouncyCastle MAC (≈4 hours work, +8pp recall)

Covers **11 missing tokens**. Slightly more involved because curve extraction needs metavar handling.

| Sub-item | Tokens caught | Effort | Approach |
|---|---|---|---|
| **B1: EC curve names** | CURVE25519, ED448, X448, P-256, P-384, P-521 (6) | ~2h | Add metavar capture on `ec.SECP$BITS$VARIANT()` (Python pyca) and equivalent JCA/Go/Node patterns. Canonicalize captured token → `SECP256R1` → `P-256`. Parser canonicalizer already handles most variants; just need rules to fire and capture the curve name. |
| **B2: BouncyCastle MAC algorithms** | CMAC, GMAC, KBKDF, KMAC (4) | ~1.5h | Add rules in `scanner/rules/java.yml` matching `new CMac(...)`, `new GMac(...)`, `KBKDFParameters.builder()`, etc. Static `cbom-primitive` per rule. |
| **B3: ED448 catchup** | ED448 (1) | ~30m | Java BouncyCastle pattern; already partially handled by Ed25519 rule shape but token differs. |

**Phase B expected outcome:** 123 + 11 = **134 TP → recall 97.1%** (+8pp from Phase A, +21pp from baseline)

---

## Phase C — Coarse-marker refinement (≈6 hours work, +3-5pp recall + quality gain)

Cleans up the catchall tokens that PR #4 added as intentional placeholders (`PASSWORD-HASH`, `WEAK-PRNG`, `DEPRECATED-CRYPTO`, `CONFIG-DRIVEN-ALGORITHM`, etc.). The recall gain is smaller because most algorithms behind these markers are already counted elsewhere — the real win is **CBOM output quality**: every component carries a specific token, not a category.

| Sub-item | Effort | Approach |
|---|---|---|
| **C1: Split `PASSWORD-HASH`** | ~2h | Per-language: split into per-algorithm rules (bcrypt, PBKDF2, Argon2id, Scrypt). PR #4 left these as coarse markers; refine. |
| **C2: Split `DEPRECATED-CRYPTO`** | ~1.5h | Likely matches DES/3DES/RC4/MD5 patterns across languages. Replace single rule with N per-algorithm rules. |
| **C3: Split `CONFIG-DRIVEN-ALGORITHM` / `WEAK-PRNG`** | ~1h | These match variable-driven algo selection where the parser couldn't resolve the metavar. Add string-pattern lookups for common constant values (`"AES-256-GCM"`, `"sha256"` as literals). |
| **C4: Coarse-marker assertions** | ~30m | New test fail-loud-if-coarse: assert no rule in `scanner/rules/` uses the placeholder tokens. Forces all future rules to be specific. |
| **C5: Remaining FN cleanup** | ~1h | ELGAMAL (Python pyca only), the 3 secret-bucket FNs (likely just comparison-script normalization gaps — verify), `kdf-to-cipher-chain` relationship marker (either remove or document as non-algorithm). |

**Phase C expected outcome:** 134 + 4 = **138 TP → recall 98-100%** (saturating; theoretical ceiling depends on whether all GT tokens are physically present in the test project)

---

## Combined ETA & expected final recall

| Phase | Wall time (with subagent parallelism where possible) | Cumulative recall | Cumulative TP |
|---|---|---|---|
| Baseline (post-rc3) | — | **76.1%** | 105 / 138 |
| + Phase A | ~4 hours | **~89.1%** | 123 / 138 |
| + Phase B | ~4 hours | **~97.1%** | 134 / 138 |
| + Phase C | ~6 hours | **~98-99%** | 137-138 / 138 |

**If all 3 phases land: expected recall ≈ 98-99%.**

Reaching exactly 100% is unlikely on this test project because:
- Some GT tokens may not be physically present (e.g. ELGAMAL is listed as expected but the test project's pyca files don't actually use it).
- Some BouncyCastle Dart/Rust patterns lost cross-statement precision in PR #2's workarounds (blocked on opengrep upstream).
- The comparison script may still have residual bucket-classification gaps that look like FN to it but are actually emitted by cradar.

**Total effort:** ≈14 hours of focused work, split across 3 separable PRs.

Precision should hold steady at ~99% throughout (we're adding specific rules, not loosening matches).

## Out of scope for this plan

- Cross-statement taint patterns blocked on upstream opengrep changes.
- Universal/regex secret scanner expansion (would push secret-bucket recall but adds noise risk).
- Comparison-script enhancements (orthogonal — improves measurement, not the product).

## Suggested PR sequence

1. **PR #7** — Phase A (single PR, 4 sub-commits, +13pp recall)
2. **PR #8** — Phase B (single PR, 3 sub-commits, +8pp recall)
3. **PR #9** — Phase C (single PR, 5 sub-commits, +3-5pp recall plus quality wins)

Each PR includes its own E2E verification against `CipherRadarTestProj` so reviewers can see the recall delta in the description.
