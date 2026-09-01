# Detection Engine

> **Document version:** v7
> **Last updated:** 2026-06-23
> **Change:** Document post-scan key-size enrichment pass (`keysize.Enrich`).

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-15 | Initial design — included "custom taint engine" as core component |
| v2 | 2026-03-16 | **Custom taint engine replaced** with three-layer approach: tree-sitter constant propagation + Semgrep taint rules + Joern deep analysis. See ADR-004 for full decision rationale. |
| v3 | 2026-03-18 | Pass 2 engine updated from Semgrep OSS to OpenGrep. Semgrep moved taint mode to commercial (Dec 2024); OpenGrep restores it under LGPL-2.1 with identical YAML rule format. See ADR-009. |
| v4 | 2026-05-29 | **Pass 3 redefined.** The Joern-based CPG Pass 3 was prototyped and removed per [ADR-033](decisions/ADR-033-remove-joern-pass3.md) — `cli/internal/joern/` is now vestigial and imported nowhere. Pass 3 is now **YARA-X binary content scanning** (opt-in) per [ADR-039](decisions/ADR-039-yarax-binary-scanning.md). Pass-2 findings now also carry quantum posture — see [quantum-coverage-matrix.md](quantum-coverage-matrix.md). |
| v5 | 2026-06-23 | Expanded Pass-2 `cbom-*-crypto-library-import` rules across 9 languages (Spring/JWT/Jasypt/Tink, jose/@noble, passlib/PyJWT, RustCrypto crates, etc.). Post-scan enrichment (`cli/internal/deps`) now resolves Maven `<dependencyManagement>` and Gradle `libs.versions.toml` catalog aliases. Full inventory: [guides/cli/cbom-schema-reference.md](guides/cli/cbom-schema-reference.md) §2.1. |
| v6 | 2026-06-23 | Cross-linked [guides/cli/algorithm-keysize-patterns.md](guides/cli/algorithm-keysize-patterns.md) — per-language key-size declaration idioms, CipherRadar coverage matrix, and detection gap priorities. |
| v7 | 2026-06-23 | Document post-scan `keysize.Enrich` pass (P0–P2 items shipped). |

---

## 1. Overview

The detection engine transforms raw source code into structured CycloneDX CBOM components. It uses three complementary passes, each with a different performance/accuracy trade-off. Pass selection is controlled by `--passes` (default `1,2`), `--deep` (alias for `1,2,3`), and `--fast` (Pass 1 only):

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DETECTION ENGINE (v4)                            │
│                                                                     │
│  Pass 1: tree-sitter + Constant Propagation    [always, fast]       │
│  ├── Direct literals and single/multi-hop variable resolution       │
│  ├── ~80% of all crypto findings                                    │
│  └── Runtime: seconds                                               │
│                                                                     │
│  Pass 2: OpenGrep Taint Rules                  [default, moderate]  │
│  ├── Declarative YAML rules per language (taint mode)               │
│  ├── ~8–10% additional findings; findings carry quantum posture     │
│  └── Runtime: minutes                                               │
│                                                                     │
│  Pass 3: YARA-X (binary content scanning)      [opt-in, --deep]    │
│  ├── Scans compiled artifacts/binaries via the `yr` engine          │
│  ├── Hard-coded keys, pinned certs, statically-linked crypto        │
│  │   library banners, algorithm byte tables (e.g. AES S-box)        │
│  └── Requires `yr` (cradar install-tools / cradar-full)            │
│                                                                     │
│  Unresolved: crypto call recorded, parameter marked unknown         │
└─────────────────────────────────────────────────────────────────────┘
```

> **Why not a custom taint engine?** The original v1 design specified a "custom taint engine." This was revised after a feasibility analysis revealed it would require 6–12 months of engineering effort to reach production quality, while proven open-source tools already solve the problem with higher accuracy. See [ADR-004](decisions/ADR-004-taint-engine-revision.md) for the full analysis.
>
> **Historical note on Pass 3.** A Joern-based Pass 3 (Code Property Graph, inter-procedural taint) was prototyped and removed per [ADR-033](decisions/ADR-033-remove-joern-pass3.md); the `cli/internal/joern/` package is vestigial and imported nowhere at runtime. The current Pass 3 is YARA-X binary content scanning per [ADR-039](decisions/ADR-039-yarax-binary-scanning.md).

---

## 2. Language Coverage Matrix

Pass 1 (tree-sitter) and Pass 2 (OpenGrep taint rules) operate **per language** — the matrix below tracks them. Pass 3 (YARA-X) is **not** a per-language pass: it scans compiled artifacts (binaries, JARs, wheels) for crypto signatures regardless of source language, so it is represented per-artifact in [§5](#5-pass-3-yara-x-binary-content-scanning) rather than as a column here.

CipherRadar ships **12 language scanners**: Java, Kotlin, Python, JS/TS, C#, Go, C/C++, Rust, PHP, Ruby, Swift, Dart.

| Language | AST Parser (Pass 1) | Pass 2 (OpenGrep) | Crypto Libraries Modelled |
|---|---|---|---|
| **Java** | tree-sitter-java | Yes | JCA/JCE, Bouncy Castle, Google Tink, Spring Security Crypto, Apache Commons Crypto |
| **Kotlin** | tree-sitter-kotlin | Yes | Same as Java + Kotlin-specific extensions |
| **Python** | tree-sitter-python | Yes | `cryptography`, PyCryptodome, `hashlib`, `ssl`, PyNaCl, `pyOpenSSL`, `passlib`; SM2/GOST/ECIES, Schnorr/BLS where modelled |
| **JavaScript** | tree-sitter-javascript | Yes | `crypto` (Node.js), `node-forge`, `jsonwebtoken`, `bcrypt`, WebCrypto API; ECIES/Schnorr where modelled |
| **TypeScript** | tree-sitter-typescript | Yes | Same as JS + typed interfaces |
| **C#** | tree-sitter-c-sharp | Yes | `System.Security.Cryptography`, BouncyCastle.NET |
| **Go** | tree-sitter-go | Yes | `crypto/*` stdlib, `golang.org/x/crypto`; SM2/GOST, BLS where modelled |
| **C/C++** | tree-sitter-c | Yes | OpenSSL, libsodium, mbedTLS, WolfSSL, GnuTLS; GOST/SM2 engines where modelled |
| **Rust** | tree-sitter-rust | Yes | `ring`, `rustls`, `openssl` crate, `aes`, `rsa`; Schnorr/BLS where modelled |
| **PHP** | tree-sitter-php | Yes | `openssl_*`, `hash_*`, `password_hash`, `sodium_*` |
| **Swift** | tree-sitter-swift | Yes | CommonCrypto, CryptoKit, Security framework |
| **Ruby** | tree-sitter-ruby | Yes | `OpenSSL`, `BCrypt`, `Digest`, `rbnacl` |
| **Dart/Flutter** | tree-sitter-dart | Yes | `package:crypto`, `package:cryptography`, `pointycastle` |

In addition to the 12 language scanners, CipherRadar runs **config scanners** (nginx, httpd, `openssl.cnf`, `java.security`, Kubernetes manifests, Dockerfile) and **binary/artifact scanners** (JAR, Python wheel, native binaries) plus the YARA-X Pass-3 scanner. Container-image scanning (`--container`) materializes layer files to a temp directory and runs the same pipeline as a directory scan (Pass 1 + Pass 3 via the walker, Pass 2 via OpenGrep).

---

## 3. Pass 1: tree-sitter + Constant Propagation

### What It Does

tree-sitter parses the source file into a Concrete Syntax Tree (CST). A custom constant propagation pass then:

1. Identifies all crypto API call expressions matching the library API model
2. For each parameter, walks backward through the assignment chain to resolve literal values
3. Handles string concatenation, integer arithmetic, and simple conditional assignments

This is **not** general taint analysis — it is constant propagation, a standard compiler technique. The scope is intentionally limited to what is needed for CBOM:

- Sources: string literals, byte array literals, integer constants
- Sinks: known crypto library function parameters
- Propagation: variable assignments, simple function return values

### Complexity Levels Handled by Pass 1

| Pattern | Example | Handled? | Confidence |
|---|---|---|---|
| Direct literal | `Cipher.getInstance("AES/CBC/PKCS5Padding")` | Yes | High |
| Single-hop variable | `String a = "AES/CBC/PKCS5Padding"; Cipher.getInstance(a)` | Yes | High |
| Concatenation | `String s = "AES" + "/CBC/PKCS5Padding"; Cipher.getInstance(s)` | Yes | High |
| Integer constant | `KeyGenerator.getInstance("AES").init(256)` | Yes | High |
| Multi-hop same function | `String a = "AES"; String b = a + "/CBC"; Cipher.getInstance(b)` | Yes | Medium |
| Simple getter same file | `getAlgo()` returns a literal string | Yes | Medium |
| Cross-file constants | `Constants.CIPHER_ALGO` declared in another file | Yes (symbol table pass) | Medium |
| Conditional return | `if (legacy) return "DES"; return "AES/GCM"` | Partial — emits both | Low |
| Config / env var | `System.getenv("ALGO")` | No — unresolved | Unresolved |
| Deep multi-hop | 5+ function hops across multiple files | No — beyond intra-procedural scope | Unresolved |

### Symbol Table Pass

Before Pass 1 runs on individual files, a **project-wide symbol table** is built in a preparatory scan:
- Collects all `static final` / `const` / module-level constant declarations
- Indexes them by fully qualified name
- Pass 1 resolves cross-file constant references against this table

---

## 4. Pass 2: OpenGrep Taint Rules

CipherRadar ships **207 OpenGrep rules** (154 inventory + 53 security) across 12 rule files (`scanner/rules/*.yml`). OpenGrep is the community fork of Semgrep used since ADR-009; the YAML rule format is identical to Semgrep's. Pass-2 findings are annotated with quantum posture (see [quantum-coverage-matrix.md](quantum-coverage-matrix.md)).

### What It Does

OpenGrep's taint mode allows declarative definition of:
- **Sources** — where tainted (or in our case, constant) values originate
- **Sinks** — crypto API call parameters
- **Sanitisers** — (not relevant for CBOM; we want to catch all crypto usage)
- **Propagators** — how taint flows through assignments and function calls

### Example OpenGrep Rule (Java)

```yaml
rules:
  - id: java-cipher-taint
    languages: [java]
    message: "Cryptographic algorithm detected: $ALGO"
    severity: INFO
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: |
              String $VAR = "...";
    pattern-sinks:
      - patterns:
          - pattern: Cipher.getInstance($ALGO)
          - pattern: MessageDigest.getInstance($ALGO)
          - pattern: KeyGenerator.getInstance($ALGO)
          - pattern: Mac.getInstance($ALGO)
          - pattern: SecretKeyFactory.getInstance($ALGO)
    pattern-propagators:
      - pattern: $X = $Y
        from: $Y
        to: $X
```

### Why OpenGrep for Pass 2

- Rules are **auditable YAML** — security team and contributors can read, review, and extend them
- No compiler knowledge required to write or maintain rules
- Covers 12+ languages with taint mode; same YAML format as Semgrep — all existing rules compatible
- Taint mode is free under LGPL-2.1 (Semgrep moved taint to commercial in Dec 2024 — see ADR-009)
- No SaaS or commercial-use restrictions on rules
- Fast enough to run on every PR (minutes, not hours)

### Crypto-library inventory rules

A subset of Pass-2 rules (`cbom-<lang>-crypto-library-import` and related) detect
**cryptographic library imports** (`import` / `require` / `use` / `#include`) and
emit findings with `cbom-asset-type: library`. These are supply-chain inventory
entries — distinct from algorithm-usage findings from Pass 1.

After scanning, `enrichLibraries()` maps each coarse `cbom-library` token to a
concrete package via `cli/internal/deps/library_map.go` and project manifests/
lockfiles. Supported enrichment ecosystems: npm, PyPI, Maven/Gradle, Cargo,
RubyGems, Go modules, Dart/pub. See [ADR-040](decisions/ADR-040-library-asset-type.md)
and [guides/cli/cbom-schema-reference.md](guides/cli/cbom-schema-reference.md) §2.1
for the monitored-library list and manifest sources.

---

## 5. Pass 3: YARA-X (Binary Content Scanning)

> **Historical note.** A Joern-based Pass 3 (Code Property Graph, inter-procedural taint) was prototyped and removed per [ADR-033](decisions/ADR-033-remove-joern-pass3.md). It is no longer a live component — the `cli/internal/joern/` package remains in the tree as vestigial dead code, imported nowhere at runtime. Pass 3 was redefined as YARA-X binary content scanning per [ADR-039](decisions/ADR-039-yarax-binary-scanning.md).

### What It Does

Pass 3 scans **compiled artifacts and binary content** — not source — using the [YARA-X](https://virustotal.github.io/yara-x/) engine (`yr`). Where source-level passes can miss crypto that is statically linked, embedded, or shipped as data, YARA-X matches binary signatures to recover it. It detects:

- **Hard-coded keys** embedded in binaries (symmetric key material, private-key blobs)
- **Pinned certificates** baked into the artifact
- **Statically-linked crypto library banners** — version strings / fingerprints of OpenSSL, libsodium, mbedTLS, BoringSSL, etc. linked into a binary
- **Algorithm byte tables** — characteristic constant tables such as the AES S-box, SHA round constants, and similar lookup tables that identify an algorithm even when symbols are stripped

YARA-X runs over the artifact scanners' inputs (raw binaries, JARs, Python wheels) as a universal scanner, so it complements rather than displaces the native JAR / wheel / binary scanners. This applies to both **directory** scans and **container-image** scans — image layers are materialized to disk and routed through Pass 3 like any other files (gh #83).

### When Pass 3 Runs

Pass 3 is **opt-in** and off by default:

- Default scan is `--passes 1,2` — Pass 3 does **not** run.
- `--deep` is an alias for `--passes 1,2,3` and enables YARA-X binary scanning.
- `--fast` runs Pass 1 only.
- Pass 3 requires the `yr` (YARA-X) binary on `PATH`. Install it via `cradar install-tools`, or use the `cradar-full` distribution which bundles it. If Pass 3 is requested explicitly (via `--deep` or `--passes` including `3`) and `yr` is missing, the scan hard-fails rather than silently downgrading.

### Why YARA-X

- Recovers crypto that source analysis cannot see (statically-linked / stripped / data-embedded)
- Mature, fast Rust rules engine; no JVM dependency (unlike the removed Joern pass)
- Signatures are auditable rules, consistent with the OpenGrep-rules philosophy
- Cheap to keep off the default hot path and enable only when deep artifact analysis is needed

---

## 6. What Gets Detected Per Asset Type

### Algorithms

| Property | Description | Example |
|---|---|---|
| `name` | Algorithm family | `AES`, `RSA`, `SHA-256` |
| `primitive` | Primitive type | `blockCipher`, `hash`, `pke`, `ae`, `mac`, `pbkdf`, `drbg`, `kem`, `signature` |
| `parameterSetIdentifier` | Key/parameter size | `256`, `2048`, `521` — see [algorithm-keysize-patterns.md](guides/cli/algorithm-keysize-patterns.md) for per-language declaration idioms and coverage gaps |
| `mode` | Cipher mode | `gcm`, `cbc`, `ecb`, `ctr`, `cfb`, `ccm` |
| `padding` | Padding scheme | `pkcs7`, `oaep`, `pss`, `pkcs1v15`, `none` |
| `curve` | Named EC curve | `secp256r1`, `Curve25519`, `brainpoolP256r1` |
| `cryptoFunctions` | Operations | `encrypt`, `decrypt`, `sign`, `verify`, `hash`, `keyDerive`, `encapsulate`, `decapsulate` |
| `classicalSecurityLevel` | Classical bits of security | `128`, `192`, `256` |
| `nistQuantumSecurityLevel` | NIST PQC level (0–6) | `0` = quantum-vulnerable; `5` = NIST level 5 PQC |
| Location | File + line + column | `src/auth/TokenService.java:142:18` |
| Confidence | Detection confidence | `high`, `medium`, `low`, `unresolved` |

### Related Cryptographic Material

Detectable patterns:

| Pattern | Example | Confidence |
|---|---|---|
| Hardcoded hex key | `byte[] key = {0x2b, 0x7e, 0x15, 0x16, ...}` | High |
| Hardcoded base64 key | `String key = "c2VjcmV0a2V5MTIzNDU2Nzg="` | High |
| Hardcoded PEM block | `-----BEGIN RSA PRIVATE KEY-----` | High |
| Static IV constant | `byte[] iv = new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}` | High |
| Static zero IV | `Arrays.fill(iv, (byte)0)` | High |
| Insecure PRNG for IV | `new Random().nextBytes(iv)` | High |
| PBKDF2 low iterations | `PBKDF2WithHmacSHA256, 1000, 256` | High |
| Hardcoded JWT secret | `Jwts.builder().signWith(Keys.hmacShaKeyFor("secret"))` | High |

### Protocols and Certificates

Refer to the original detection coverage in v1 — this section is unchanged.

---

## 7. Revised Accuracy Expectations

| Scenario | Expected Accuracy | Primary Pass |
|---|---|---|
| Direct literal | ~98% | Pass 1 |
| Single-hop variable | ~92% | Pass 1 |
| Multi-hop same function | ~82% | Pass 1 + Pass 2 |
| Cross-function same file | ~76% | Pass 2 (OpenGrep) |
| Cross-file constants class | ~70% | Pass 1 (symbol table) + Pass 2 (OpenGrep) |
| Deep multi-hop cross-file | ~55–65% | Pass 2 (OpenGrep taint); residual marked `unresolved` |
| Crypto in compiled artifacts | (recovered) | Pass 3 (YARA-X, `--deep`) |
| Runtime / config-driven | ~0% (unresolvable by source analysis) | Marked `unresolved` |
| **Overall real-world** | **~85–90%** | Weighted by pattern prevalence |

The ~85–90% overall figure is based on the real-world distribution of crypto patterns: ~80–85% of crypto API calls use direct literals or single-hop variables (Pass 1 territory). See ADR-004 for the full analysis.

### Known limitations — misuse detection requiring data-flow

Detection identifies *what* cryptographic asset is present; flagging *insecure
configuration of a correctly-identified asset* sometimes needs semantic/taint
analysis beyond anchored pattern matching. Two such cases are known deferred
false negatives (the only 2 FNs on the benchmark corpus; both `quantum-safe`,
i.e. security-hygiene not PQC-relevant) — tracked in **issue #45**:

- **Fixed-seed `SecureRandom`** — `new SecureRandom(<literal bytes>)` is
  predictable; distinguishing it from legitimate seeded use needs argument
  analysis.
- **Static / reused IV with a block cipher** — a constant `byte[]` IV flowing
  into `Cipher.init(...)` needs data-flow to connect the IV field to the cipher.

Both are deferred because naive rules would false-positive (legitimate seeded
RNG, arbitrary 16-byte arrays), violating the zero-false-positive requirement.

---

## 8. Confidence Scoring

Every finding carries an explicit confidence level:

| Level | Meaning | Example |
|---|---|---|
| **High** | Algorithm is a literal constant directly passed to the API or resolved via single-hop constant propagation | `Cipher.getInstance("AES/CBC/PKCS5Padding")` |
| **Medium** | Resolved via multi-hop constant propagation or cross-file symbol table | Algorithm via constants class |
| **Low** | Resolved via deeper Pass-2 taint flow or recovered from a binary signature (Pass 3 / YARA-X) — possible but not certain | Taint path across functions; statically-linked library banner |
| **Unresolved** | Crypto API call confirmed; algorithm parameter is runtime-determined | `Cipher.getInstance(config.getAlgo())` |

Low and Unresolved findings are reported separately. Policy rules can be configured to act — or not act — on Low/Unresolved findings. Unresolved findings are still valid CBOM entries: they record the crypto API call location for manual review.

---

## 9. Suppression

Refer to the suppression mechanisms documented in v1 (inline comments, `.cradarignore` file) — unchanged. (Renamed from `.cbomignore` following the binary rename in [ADR-024](decisions/ADR-024-cli-binary-rename.md).)
