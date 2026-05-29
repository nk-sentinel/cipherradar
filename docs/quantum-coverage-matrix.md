# Tier-1 Quantum-Vulnerable Family Coverage Matrix

**Last audited:** 2026-05-29 (issue [#34](https://github.com/nk-sentinel/cipherradar/issues/34))

This document records, per language, whether CipherRadar can detect each
**Tier-1 (mainstream) quantum-vulnerable cryptographic family**. It is the
authoritative coverage reference and reflects the *actual* state of the
scanners and rule corpus at the audit date above.

## What "Tier-1" means

Tier-1 families are the widely-deployed asymmetric primitives broken by
Shor's algorithm: integer factorization (RSA), finite-field and
elliptic-curve discrete log (DSA, DH, ECDH, ECDSA, EC, ElGamal), and the
Edwards/Montgomery curve schemes (Ed25519, Ed448, X25519, X448). Every cell
marked detected is also classified `quantum-vulnerable` by the shared quantum
readiness table (`cli/internal/scanner/quantum/quantum-readiness.yml`).

## Legend

| Symbol | Meaning |
| --- | --- |
| ✅ | Detected with a dedicated, high/medium-confidence rule or scanner pattern. |
| ◐ | Partial — detected only indirectly (folded into a broader family finding) or only for a subset of common libraries/idioms. See per-language notes. |
| ❌ | Not detected. Either the language has no common API for that family, or the API is too niche to detect without false-positive risk. |

How the matrix was built: by inspecting `scanner/rules/*.yml` (Pass-2 OpenGrep
rules) and `cli/internal/scanner/<lang>/*.go` (Pass-1 AST/regex scanners), and
confirmed empirically by scanning per-family fixtures with
`cradar scan --passes 1,2`.

> **TypeScript** shares the JavaScript scanner and the
> `languages: [javascript, typescript]` rule set, so its coverage is identical
> to JavaScript and is listed in the same column (**JS/TS**).

## Matrix

| Family \ Language | java | kotlin | python | JS/TS | csharp | go | cpp | rust | php | ruby | swift | dart |
| --- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| **RSA**     | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DSA**     | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ | ❌ | ❌ |
| **DH**      | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **ECDH**    | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ◐ | ✅ | ❌ |
| **ECDSA**   | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ |
| **EC** (+curves) | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ |
| **Ed25519** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Ed448**   | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **X25519**  | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ◐ | ✅ | ✅ | ❌ | ✅ | ❌ |
| **X448**    | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ElGamal** | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

## Per-language notes

- **java** — Full Tier-1 coverage. Standard JCA factories (`KeyPairGenerator`,
  `Signature`, `KeyAgreement`) plus BouncyCastle classes cover Ed448, the
  Ed25519 variants (ph/ctx), X448 and ElGamal.
- **kotlin** — JCA-based, structurally mirrors Java. `KeyAgreement` detection
  (DH, ECDH, X25519, X448) was **added in #34** — previously these were blank.
  Ed448/ElGamal remain ❌: they require BouncyCastle classes Kotlin code rarely
  uses and the Kotlin scanner has no BC-constructor pass.
- **python** — Full Tier-1 coverage via `cryptography` (pyca) dedicated key
  classes, with ElGamal covered through PyCryptodome.
- **JS/TS** — Node `crypto.generateKeyPair*` named types cover RSA/DSA/EC/ECDH/
  Ed25519/Ed448/X25519/X448; P-curve rules cover EC. ElGamal ❌ — no common
  Node/browser API.
- **csharp** — DSA and ECDH (`ECDiffieHellman.Create()`) were **added in #34**.
  EC is ◐ (folded into ECDsa, no standalone EC finding). Ed25519/Ed448/X25519/
  X448/ElGamal ❌ — .NET BCL has no built-in API (BouncyCastle.NET only).
- **go** — stdlib `crypto/*` packages cover RSA/DSA/ECDSA/EC/Ed25519, and
  `crypto/ecdh` covers ECDH and X25519. DH/Ed448/X448/ElGamal ❌ — not in the
  standard library.
- **cpp** — OpenSSL classic-API detection for DSA, DH, EC, ECDSA, ECDH was
  **added in #34**. X25519 is ◐: detected via libsodium `crypto_*`, but the
  OpenSSL `EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, …)` path is currently
  attributed to RSA because the NID argument is not parsed. Ed448/X448/ElGamal
  ❌.
- **rust** — Covers the `ring`/`aws-lc-rs` idioms (RSA, ECDSA, Ed25519, and
  ECDH/X25519 via `agreement::*`). DSA is ◐ — only the RustCrypto `dsa` crate
  signing path is recognized in limited cases. The RustCrypto trait-based
  ecosystem (`p256`, `ed25519-dalek`, `x25519-dalek`) is **not** broadly
  matched; Ed448/X448/ElGamal ❌.
- **php** — `openssl_pkey_new` key types cover RSA/DSA/DH/EC; `openssl_sign`
  covers ECDSA; libsodium `sodium_crypto_sign*` / `sodium_crypto_box*` cover
  Ed25519 / X25519. ECDH is ◐ (folded into the EC key finding). Ed448/X448/
  ElGamal ❌.
- **ruby** — `OpenSSL::PKey::{RSA,DSA,EC}` cover RSA/DSA/EC; ECDSA and ECDH are
  ◐ because Ruby's single `EC` key object serves both signing and agreement and
  is reported as one EC finding. DH/Ed25519/X25519/Ed448/X448/ElGamal ❌.
- **swift** — CryptoKit `P256/P384/P521` and `Curve25519` cover ECDSA, ECDH,
  Ed25519, X25519. RSA via `SecKeyCreateRandomKey`. EC is ◐: a `SecKey` EC key
  is currently attributed to RSA (the keytype attribute is not inspected).
  DSA/DH/Ed448/X448/ElGamal ❌.
- **dart** — pointycastle `RSAEngine`, `ECKeyGenerator`/`ECDSASigner` cover RSA,
  EC, ECDSA. pointycastle has no Ed25519/X25519/DH/DSA/ElGamal classes in
  common use, so those remain ❌.

## Gaps filled in #34

| Language | Families added | Mechanism |
| --- | --- | --- |
| kotlin | DH, ECDH, X25519, X448 | Pass-1 `KeyAgreement.getInstance()` handler + family map entries |
| csharp | DSA, ECDH | Pass-1 `.Create()` factory map (`DSA`, `ECDiffieHellman`) |
| cpp | DSA, DH, EC, ECDSA, ECDH | Pass-1 OpenSSL classic-API function-call detection |

## Known open gaps (intentionally left ❌)

These were evaluated and deliberately not implemented in #34 to avoid
false-positive risk or because no common API exists:

- **C++ OpenSSL X25519/X448/Ed448 via EVP** — would require parsing the `NID`
  argument of `EVP_PKEY_CTX_new_id`; the generic context is currently labeled
  RSA. A correct fix is a separate, larger change.
- **Rust RustCrypto trait ecosystem** (`p256`, `ed25519-dalek`, `x25519-dalek`)
  — broad type/trait matching carries meaningful FP risk; only `ring`-style
  idioms are covered today.
- **Swift / C# EC keys via `SecKey` / generic factories** — attributed to RSA;
  distinguishing the key type needs argument inspection.
- **ElGamal outside Java/Python**, **Ed448/X448 outside Java/Python/JS** — niche
  or library-specific APIs with no common idiom in those languages.

### Quantum-vulnerable families: classify-only, no detector

- **Rabin** (won't-fix) — present in `quantum-readiness.yml` as `quantum-vulnerable`,
  so it classifies correctly if surfaced, but there is **no detection rule**. No
  mainstream library exposes a stable, anchorable Rabin cryptosystem API (no
  dedicated package or BouncyCastle engine class); a rule would have to match the
  bare word "rabin", violating the zero-false-positive requirement. Tracked and
  closed in epic #31 / follow-up #41.
- **SRP / SPAKE (PAKE)** — scoped out of the current quantum-coverage effort as
  lower priority; revisit in a future issue if needed.
