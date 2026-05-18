# Inventory Recall Improvement Plan

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
