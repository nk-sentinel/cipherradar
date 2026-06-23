# Algorithm Key-Size Declaration Patterns

> **Document version:** v2
> **Created:** 2026-06-23
> **Last updated:** 2026-06-23
> **Status:** Active
> **Purpose:** Reference for how cryptographic key and parameter sizes are declared across
> languages and APIs, what CipherRadar captures today, and known detection gaps.

This document supports implementation of Pass 1 key-size extraction, CBOM
`parameterSetIdentifier` population, and policy checks (`min_key_size`). For how sizes appear
in CycloneDX output, see [cbom-schema-reference.md](cbom-schema-reference.md) §4.1. For the
JCA method-chaining fix shipped in v0.4.0-rc.1, see CHANGELOG § "Key-size capture from
method-chaining" (PR #53, commit `d07b1d2`).

---

## 1. Internal model and CBOM mapping

### 1.1 Scanner field

Pass 1 scanners set `types.CryptoProperties.KeySize` as an **integer bit count** (e.g. `256`,
`2048`). Certificates use a separate field: `SubjectPublicKeySize` (from X.509 parsing).

### 1.2 CycloneDX output (canonical)

The CLI maps `KeySize` in `cli/internal/output/converter.go`:

| Internal | CycloneDX field | Type | Example |
|---|---|---|---|
| `KeySize` | `algorithmProperties.parameterSetIdentifier` | string | `"2048"` |
| `KeySize` (when `ClassicalSecurity` unset) | `algorithmProperties.classicalSecurityLevel` | int | `2048` |
| `KeySize` | component `name` suffix | string | `RSA-2048` |

`deriveParameterSet()` resolves the parameter set in this order:

1. PQC token suffix (`ML-KEM-768` → `768`)
2. First numeric segment in `AlgorithmPrimitive` (`AES-256-GCM` → `256`)
3. Explicit `KeySize`

**Important:** Many findings encode size only in `Name` (e.g. `AES-256-CBC`) without setting
`KeySize`. In those cases `parameterSetIdentifier` is often empty even though the human-readable
name contains a size.

### 1.3 What is not key size

| Pattern | Example | Why it is not key size |
|---|---|---|
| Digest output width | `SHA-256`, `sha256()` | Hash output bits, not a symmetric key |
| AES block size | 128 bits | Fixed block size; key can be 128/192/256 |
| Protocol version | `TLS 1.2` | Protocol revision, not key width |
| PBKDF2 iteration count | `10000` in `PBKDF2WithHmacSHA256, 10000, 256` | Iterations; last arg may be derived key length |

---

## 2. Taxonomy — seven declaration patterns

| ID | Pattern | Description |
|---|---|---|
| **A** | Separate init call | Algorithm selected first; size on a later statement |
| **B** | Constructor / factory arg | Size passed at object creation |
| **C** | Keyword / named option | Size in config object or keyword argument |
| **D** | Embedded in algorithm string | Size part of cipher or method name |
| **E** | Type / class name | Size encoded in the type (`Aes256Gcm`, `P256`) |
| **F** | Curve name → implicit size | EC / Ed25519: curve implies bit strength |
| **G** | Config / policy file | Size in deployment config, not application code |

---

## 3. Per-language patterns and CipherRadar coverage

Legend: **✅** = Pass 1 sets `KeySize` today · **◐** = partial (name or curve only) · **❌** = not captured

### 3.1 Java / Kotlin (JCA / JCE)

| Pattern | Example | Detected |
|---|---|---|
| A — key-pair init | `kpg.initialize(2048)` | ✅ |
| A — two-arg init | `kpg.initialize(new SecureRandom(), 2048)` | ❌ (gap; fix planned) |
| A — symmetric init | `kg.init(256)` | ✅ |
| F — EC curve spec | `new ECGenParameterSpec("secp256r1")` | ✅ (curve → 256) |
| D — cipher string | `Cipher.getInstance("AES/GCM/NoPadding")` | ❌ |
| B — inline chain | `KeyPairGenerator.getInstance("RSA").initialize(2048)` | ❌ |
| B — BC low-level | `RSAKeyGenerationParameters(..., 2048, 80)` | ❌ |

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);                                    // ✅

KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);                                            // ✅

kpg.initialize(new ECGenParameterSpec("secp256r1"));   // ✅ → 256

Cipher.getInstance("AES/CBC/PKCS5Padding");              // ❌ no KeySize
```

**Kotlin:** Same JCA idioms. Init-size patching uses regex on raw source because the Java
tree-sitter grammar misparses semicolon-free Kotlin chains.

**Pass 2:** Curve inventory rules (`cbom-java-ec-curve-from-ecgenparameterspec`,
`cbom-java-bc-curve-p-*`) capture curve **names**, not numeric `parameterSetIdentifier`.

---

### 3.2 C# (.NET)

| Pattern | Example | Detected |
|---|---|---|
| B — factory arg | `RSA.Create(4096)` | ✅ |
| A — property assign | `rsa.KeySize = 2048` after `RSA.Create()` | ✅ |
| F — ECDsa curve | `ECDsa.Create(ECCurve.NamedCurves.nistP256)` | ❌ |
| C — AES property | `aes.KeySize = 256` | ❌ (RSA only tracked) |

```csharp
var rsa = RSA.Create(2048);           // ✅
rsa.KeySize = 3072;                   // ✅

var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);  // ❌
```

---

### 3.3 Python (pyca/cryptography, PyCryptodome)

| Pattern | Example | Detected |
|---|---|---|
| C — RSA kwarg | `rsa.generate_private_key(..., key_size=2048)` | ✅ |
| C — DH kwarg | `dh.generate_parameters(..., key_size=2048)` | ✅ |
| B — DSA positional | `dsa.generate_private_key(2048, g, p, q)` | ✅ |
| F — EC curve | `ec.generate_private_key(curve=ec.SECP256R1())` | ❌ |
| E — class name | `algorithms.AES256(...)` | ❌ |
| B — PyCryptodome | `RSA.generate(2048)` | ❌ |

```python
rsa.generate_private_key(public_exponent=65537, key_size=2048)  # ✅
ec.generate_private_key(ec.SECP384R1())                        # ❌
```

---

### 3.4 JavaScript / TypeScript (Node crypto, Web Crypto, forge)

| Pattern | Example | Property | Detected |
|---|---|---|---|
| D — cipher string | `createCipheriv('aes-256-gcm', ...)` | embedded | ✅ |
| C — Node RSA | `generateKeyPair('rsa', { modulusLength: 2048 })` | `modulusLength` | ✅ |
| C — forge RSA | `forge.pki.rsa.generateKeyPair({ bits: 2048 })` | `bits` | ✅ |
| C — Web Crypto RSA | `subtle.generateKey({ modulusLength: 2048 })` | `modulusLength` | ✅ |
| C — Web Crypto AES | `subtle.generateKey({ length: 256 })` | `length` | ✅ |
| F — ECDH curve | `createECDH('prime256v1')` | curve name | ❌ |

```javascript
crypto.createCipheriv('aes-256-gcm', key, iv);                        // ✅
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });           // ✅
forge.pki.rsa.generateKeyPair({ bits: 2048 });                        // ✅
crypto.createECDH('prime256v1');                                      // ❌
```

---

### 3.5 Go (stdlib + x/crypto)

| Pattern | Example | Detected |
|---|---|---|
| B — RSA bits arg | `rsa.GenerateKey(rand.Reader, 2048)` | ✅ |
| D — ECDH type | `ecdh.P256()` | ◐ (name only) |
| B — AES key slice | `aes.NewCipher(key)` | ❌ (`len(key)` not analyzed) |
| F — ECDSA curve | `ecdsa.GenerateKey(elliptic.P384(), rand)` | ❌ |

```go
rsa.GenerateKey(rand.Reader, 2048)  // ✅
aes.NewCipher(key)                  // ❌
```

---

### 3.6 Rust (RustCrypto, openssl crate)

| Pattern | Example | Detected |
|---|---|---|
| E — aes-gcm types | `Aes256Gcm::new(...)`, `Aes128Gcm::new(...)` | ✅ |
| B — rsa crate | `RsaPrivateKey::new(&mut rng, 2048)` | ✅ |
| D — openssl cipher | `Cipher::aes_256_gcm()` | ◐ (name only) |
| B — openssl RSA | `Rsa::generate(2048, ...)` | ❌ |

```rust
let _ = Aes256Gcm::new(key.into());              // ✅ KeySize=256
let key = RsaPrivateKey::new(&mut rng, 2048)?;   // ✅
```

---

### 3.7 Ruby (OpenSSL gem)

| Pattern | Example | Detected |
|---|---|---|
| B — RSA | `OpenSSL::PKey::RSA.new(2048)` / `.generate(2048)` | ✅ |
| B — DSA | `OpenSSL::PKey::DSA.new(2048)` | ❌ |
| D — cipher string | `OpenSSL::Cipher.new('aes-256-cbc')` | ◐ (name only) |

---

### 3.8 PHP (OpenSSL extension)

| Pattern | Example | Detected |
|---|---|---|
| D — method string | `openssl_encrypt(..., 'AES-256-CBC', ...)` | ◐ (name only) |
| C — keygen config | `openssl_pkey_new(['private_key_bits' => 2048, ...])` | ❌ |

```php
openssl_encrypt($data, 'AES-256-GCM', $key);  // name=AES-256-GCM, KeySize=0

$config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
openssl_pkey_new($config);  // family=rsa, KeySize=0
```

---

### 3.9 Swift (CryptoKit, Security, CommonCrypto)

| Pattern | Example | Detected |
|---|---|---|
| E — curve types | `P256.Signing.PrivateKey()`, `P384`, `P521` | ◐ (name only) |
| C — SymmetricKey | `SymmetricKey(size: .bits256)` | ❌ |
| C — SecKey attrs | `SecKeyCreateRandomKey([.keySizeInBits: 2048], ...)` | ❌ |

No Pass 1 scanner sets `KeySize` for Swift today.

---

### 3.10 Dart (crypto, encrypt, pointycastle)

| Pattern | Example | Detected |
|---|---|---|
| package:encrypt | `AES(key, mode: AESMode.gcm)` | ❌ |
| PointyCastle | `RSAEngine()`, `AESFastEngine()` | ❌ |

No Pass 1 scanner sets `KeySize` for Dart today.

---

### 3.11 C / C++ (OpenSSL, libsodium)

| Pattern | Example | Detected |
|---|---|---|
| B — RSA legacy | `RSA_generate_key(2048, 65537, ...)` | ✅ |
| B — RSA ex | `RSA_generate_key_ex(rsa, 2048, ...)` | ✅ |
| B — AES set key | `AES_set_encrypt_key(key, 256, &schedule)` | ❌ |
| D — EVP cipher | `EVP_aes_256_gcm()` | ◐ (name only) |
| F — EC NID | `EC_KEY_new_by_curve_name(NID_secp256r1)` | ❌ |

---

### 3.12 Config / deployment files

| Source | Pattern | Detected |
|---|---|---|
| `openssl.cnf` | `default_bits = 2048` | ✅ (+ HIGH if &lt; 2048) |
| `java.security` | `jdk.tls.disabledAlgorithms=DH keySize < 2048` | ❌ (disabled-alg lists only) |
| nginx / httpd | TLS cert paths | cert `SubjectPublicKeySize` via X.509 parse |
| k8s Secrets | embedded certs | `SubjectPublicKeySize` |

Scanner: `cli/internal/scanner/configfile/openssl_cnf.go`.

---

## 4. Pass 2 (OpenGrep) — curves vs numeric size

OpenGrep rules do **not** extract numeric key sizes (no rules for `2048`, `modulusLength`,
`key_size`, etc.).

Pass 2 **does** capture named curves as inventory metadata:

| Rule family | Languages | Output |
|---|---|---|
| `cbom-*-ec-curve-from-ecgenparameterspec` | Java | `$CURVE` metavar |
| `cbom-*-bc-curve-p-256-secp256r1` (and P-384, P-521) | Java, Python, Go, JS | `cbom-primitive: P-256` |
| `cbom-*-curve-x25519` | Python, Go | curve inventory |

These label the curve; they do not populate `parameterSetIdentifier` unless Pass 1 also maps
the curve to bits.

---

## 5. Coverage summary matrix

| Language | Sets `KeySize`? | Primary idioms covered | Biggest gaps |
|---|---|---|---|
| Java / Kotlin | ✅ | JCA init chain, EC curves | Inline chain, BC low-level, cipher strings |
| C# | ◐ | RSA factory + `KeySize` property | ECDsa/AES curves and properties |
| Python | ✅ | pyca `key_size`, DSA positional | PyCryptodome, EC curves, AES class names |
| JavaScript | ✅ | cipher strings, `modulusLength`, `bits`, `length` | EC `namedCurve`, noble/jose |
| Go | ◐ | `rsa.GenerateKey` bits | AES key len, ECDH/ECDSA curves |
| Rust | ✅ | `Aes*Gcm` types, `RsaPrivateKey::new` | openssl generate, ring constants |
| Ruby | ◐ | OpenSSL RSA.new/generate | DSA, cipher strings → KeySize |
| PHP | ❌ | — | `private_key_bits`, cipher strings |
| Swift | ❌ | — | P256/P384/P521, SymmetricKey, SecKey |
| Dart | ❌ | — | all patterns |
| C / C++ | ◐ | OpenSSL RSA generate | AES_set_encrypt_key, DSA/DH/EC |
| Config | ◐ | openssl.cnf `default_bits` | java.security keySize policy |

---

## 6. Common EC curve → bit mappings

Shared table for Pass 1 enrichment and Pass 2 curve rules:

| Curve name(s) | Bits |
|---|---|
| `secp256r1`, `P-256`, `prime256v1`, `nistP256` | 256 |
| `secp384r1`, `P-384`, `nistP384` | 384 |
| `secp521r1`, `P-521`, `nistP521` | 521 |
| `secp256k1` | 256 |
| `X25519`, `Curve25519`, `Ed25519` | 256 |
| `X448` | 448 |

Java Pass 1 already maps a subset in `detectECGenParameterSpec` (`java_scanner.go`).

---

## 7. Recommended implementation priority (CLI)

| Priority | Work item | Status |
|---|---|---|
| **P0** | Parse numeric segment from `Name` into `KeySize` (`keysize.Enrich`) | ✅ Shipped |
| **P1** | `private_key_bits` in `openssl_pkey_new` | ✅ Shipped |
| **P1** | Shared EC curve → bits table (`keysize.CurveBits` / `InferFromCurveName`) | ✅ Shipped (enrichment pass) |
| **P2** | `AES_set_encrypt_key(..., bits, ...)` | ✅ Shipped |
| **P2** | Ruby `DSA.new(N)`, C# `Aes.KeySize` | ✅ Shipped |
| **P2** | JCA two-arg `initialize(SecureRandom, N)` | ✅ Shipped |
| **P3** | PyCryptodome `RSA.generate(N)` | ❌ Planned |
| **P3** | Inline method chaining | ❌ Planned |

Implementation lives in `cli/internal/scanner/keysize/` with a post-scan hook in
`cli/internal/cmd/scan.go` (after library enrichment, before CBOM conversion).

---

## 8. Related code and docs

| Resource | Path |
|---|---|
| JCA init chaining (Java) | `cli/internal/scanner/java/java_scanner.go` — `applyKeyGenInitSizes` |
| JCA init chaining (Kotlin) | `cli/internal/scanner/kotlin/kotlin_scanner.go` — regex fallback |
| C# property chaining | `cli/internal/scanner/csharp/csharp_scanner.go` |
| CBOM parameter set derivation | `cli/internal/output/converter.go` — `deriveParameterSet` |
| Policy min key size | `cli/internal/policy/evaluator.go` |
| CycloneDX field reference | [cbom-schema-reference.md](cbom-schema-reference.md) §4.1 |
| Detection engine overview | [03-detection-engine.md](../../03-detection-engine.md) §6 |

---

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-06-23 | Initial cross-language key-size pattern reference | Key-size bug investigation |
| v2 | 2026-06-23 | Mark P0–P2 items shipped; document `keysize` enrichment package | Key-size implementation |
