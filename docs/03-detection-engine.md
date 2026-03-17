# Detection Engine

> **Document version:** v2
> **Last updated:** 2026-03-16
> **Change:** Taint engine approach revised — see [ADR-004](decisions/ADR-004-taint-engine-revision.md) for full history and rationale.

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-15 | Initial design — included "custom taint engine" as core component |
| v2 | 2026-03-16 | **Custom taint engine replaced** with three-layer approach: tree-sitter constant propagation + Semgrep taint rules + Joern deep analysis. See ADR-004 for full decision rationale. |

---

## 1. Overview

The detection engine transforms raw source code into structured CycloneDX CBOM components. It uses three complementary layers, each with a different performance/accuracy trade-off:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DETECTION ENGINE (v2)                            │
│                                                                     │
│  Pass 1: tree-sitter + Constant Propagation    [always, fast]       │
│  ├── Direct literals and single/multi-hop variable resolution       │
│  ├── ~80% of all crypto findings                                    │
│  └── Runtime: seconds                                               │
│                                                                     │
│  Pass 2: Semgrep Taint Rules                   [PR/push, moderate]  │
│  ├── Declarative YAML rules per language                            │
│  ├── ~8–10% additional findings                                     │
│  └── Runtime: minutes                                               │
│                                                                     │
│  Pass 3: Joern (CPG-based)                     [nightly, deep]      │
│  ├── Full Code Property Graph — inter-procedural taint              │
│  ├── ~3–5% additional findings (hard cases)                        │
│  └── Runtime: minutes to hours (large codebases)                   │
│                                                                     │
│  Unresolved: crypto call recorded, parameter marked unknown         │
└─────────────────────────────────────────────────────────────────────┘
```

> **Why not a custom taint engine?** The original v1 design specified a "custom taint engine." This was revised after a feasibility analysis revealed it would require 6–12 months of engineering effort to reach production quality, while proven open-source tools (Joern, Semgrep) already solve the problem with higher accuracy. See [ADR-004](decisions/ADR-004-taint-engine-revision.md) for the full analysis.

---

## 2. Language Coverage Matrix

| Language | AST Parser | Pass 2 (Semgrep) | Pass 3 (Joern) | Crypto Libraries Modelled |
|---|---|---|---|---|
| **Java** | tree-sitter-java | Yes | Yes | JCA/JCE, Bouncy Castle, Google Tink, Spring Security Crypto, Apache Commons Crypto |
| **Kotlin** | tree-sitter-kotlin | Yes | Yes | Same as Java + Kotlin-specific extensions |
| **Python** | tree-sitter-python | Yes | Yes | `cryptography`, PyCryptodome, `hashlib`, `ssl`, PyNaCl, `pyOpenSSL`, `passlib` |
| **JavaScript** | tree-sitter-javascript | Yes | Yes | `crypto` (Node.js), `node-forge`, `jsonwebtoken`, `bcrypt`, WebCrypto API |
| **TypeScript** | tree-sitter-typescript | Yes | Yes | Same as JS + typed interfaces |
| **C#** | tree-sitter-c-sharp | Yes | No (Joern roadmap) | `System.Security.Cryptography`, BouncyCastle.NET |
| **Go** | tree-sitter-go | Yes | Yes | `crypto/*` stdlib, `golang.org/x/crypto` |
| **C/C++** | tree-sitter-c | Yes | Yes | OpenSSL, libsodium, mbedTLS, WolfSSL, GnuTLS |
| **Rust** | tree-sitter-rust | Yes | No (roadmap) | `ring`, `rustls`, `openssl` crate, `aes`, `rsa` |
| **PHP** | tree-sitter-php | Yes | Yes | `openssl_*`, `hash_*`, `password_hash`, `sodium_*` |
| **Swift** | tree-sitter-swift | Yes | No (roadmap) | CommonCrypto, CryptoKit, Security framework |
| **Ruby** | tree-sitter-ruby | Yes | Yes | `OpenSSL`, `BCrypt`, `Digest`, `rbnacl` |
| **Dart/Flutter** | tree-sitter-dart | Yes | No (roadmap) | `package:crypto`, `package:cryptography`, `pointycastle` |

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
| Deep multi-hop | 5+ function hops across multiple files | No — deferred to Pass 3 | Unresolved → Pass 3 |

### Symbol Table Pass

Before Pass 1 runs on individual files, a **project-wide symbol table** is built in a preparatory scan:
- Collects all `static final` / `const` / module-level constant declarations
- Indexes them by fully qualified name
- Pass 1 resolves cross-file constant references against this table

---

## 4. Pass 2: Semgrep Taint Rules

### What It Does

Semgrep's taint mode allows declarative definition of:
- **Sources** — where tainted (or in our case, constant) values originate
- **Sinks** — crypto API call parameters
- **Sanitisers** — (not relevant for CBOM; we want to catch all crypto usage)
- **Propagators** — how taint flows through assignments and function calls

### Example Semgrep Rule (Java)

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

### Why Semgrep for Pass 2

- Rules are **auditable YAML** — security team and contributors can read, review, and extend them
- No compiler knowledge required to write or maintain rules
- Covers 30+ languages with the same rule format
- Built-in taint mode handles intra and simple inter-procedural flows
- Active community rule ecosystem (5,000+ rules) — many crypto rules already exist
- Fast enough to run on every PR (minutes, not hours)

---

## 5. Pass 3: Joern (Code Property Graph)

### What It Does

Joern builds a **Code Property Graph (CPG)** — a unified graph that combines:
- AST (Abstract Syntax Tree)
- CFG (Control Flow Graph)
- PDG (Program Dependence Graph)
- Call graph

This enables full inter-procedural taint queries across the entire project:

```scala
// Joern query: find all taint paths from string literals to Cipher.getInstance
val source = cpg.literal.typeFullName("java.lang.String")
val sink   = cpg.call.methodFullName("javax.crypto.Cipher.getInstance")
sink.reachableByFlows(source).l
```

### When Pass 3 Runs

- **Not** on every commit — too slow for interactive use
- Triggered on: merge to main, nightly schedule, manual "deep scan" request
- Results are stored and diff'd against the previous deep scan
- New findings from Pass 3 are surfaced as `confidence: low` in the dashboard

### Joern Language Support (Relevant to CipherRadar)

| Language | Joern Support | Notes |
|---|---|---|
| Java | Full | Mature; production-grade |
| Kotlin | Full | Via Java bytecode analysis |
| JavaScript / TypeScript | Full | `joern-cli` with JS frontend |
| Python | Full | CPython frontend |
| C / C++ | Full | Original Joern use case; excellent |
| PHP | Partial | PHP frontend available; maturing |
| Go | Partial | Community frontend; maturing |
| Ruby | Partial | Community frontend |
| C# | Roadmap | Not yet available |

### Joern Integration Approach

Joern is a JVM tool (Scala). Integration options:
1. **Subprocess**: CLI invocation with JSON output — simplest; no JVM in the Go CLI
2. **HTTP API**: Joern exposes a REST API (`joern-server`) — recommended for the server deployment
3. **Embedded**: Via JNI — complex; not recommended

The subprocess / HTTP API approach is used. Joern results are ingested and merged with Pass 1 + Pass 2 findings, with deduplication by file + line + sink type.

---

## 6. What Gets Detected Per Asset Type

### Algorithms

| Property | Description | Example |
|---|---|---|
| `name` | Algorithm family | `AES`, `RSA`, `SHA-256` |
| `primitive` | Primitive type | `blockCipher`, `hash`, `pke`, `ae`, `mac`, `pbkdf`, `drbg`, `kem`, `signature` |
| `parameterSetIdentifier` | Key/parameter size | `256`, `2048`, `521` |
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
| Cross-function same file | ~76% | Pass 2 (Semgrep) |
| Cross-file constants class | ~70% | Pass 1 (symbol table) + Joern |
| Deep multi-hop cross-file | ~55–65% | Pass 3 (Joern) |
| Runtime / config-driven | ~0% (unresolvable by any tool) | Marked `unresolved` |
| **Overall real-world** | **~85–90%** | Weighted by pattern prevalence |

The ~85–90% overall figure is based on the real-world distribution of crypto patterns: ~80–85% of crypto API calls use direct literals or single-hop variables (Pass 1 territory). See ADR-004 for the full analysis.

---

## 8. Confidence Scoring

Every finding carries an explicit confidence level:

| Level | Meaning | Example |
|---|---|---|
| **High** | Algorithm is a literal constant directly passed to the API or resolved via single-hop constant propagation | `Cipher.getInstance("AES/CBC/PKCS5Padding")` |
| **Medium** | Resolved via multi-hop constant propagation or cross-file symbol table | Algorithm via constants class |
| **Low** | Resolved via Joern inter-procedural analysis — possible but not certain | Deep taint path across multiple files |
| **Unresolved** | Crypto API call confirmed; algorithm parameter is runtime-determined | `Cipher.getInstance(config.getAlgo())` |

Low and Unresolved findings are reported separately. Policy rules can be configured to act — or not act — on Low/Unresolved findings. Unresolved findings are still valid CBOM entries: they record the crypto API call location for manual review.

---

## 9. Suppression

Refer to the suppression mechanisms documented in v1 (inline comments, `.cbomignore` file) — unchanged in v2.
