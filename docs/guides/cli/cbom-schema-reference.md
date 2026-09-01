# CBOM Output Schema Reference

How to read a `cradar` CycloneDX 1.7 CBOM: the two classification levels
(`components[].type` and `cryptoProperties.assetType`), the complete set of values
`cradar` emits under each, and which fields signal that **action** is required.

This is a consumer-facing reference for anyone writing ingestion code, `jq` filters,
or dashboards on top of `cradar scan -o cbom.json`. The authoritative enum source is
`cli/internal/cyclonedx17/enums.go` and `cli/internal/types/enums.go`; this doc tracks
them.

---

## 1. The two classification levels

A CBOM `components[]` entry is classified at two levels. The relationship is
**one-to-one per component** — each component has exactly one `type`, and (when it is a
cryptographic asset) exactly one `assetType`. There is no nesting of multiple asset
types inside a single component.

```
components[]
├── type: "library"                  → no cryptoProperties      (a crypto-library import)
└── type: "cryptographic-asset"      → cryptoProperties.assetType ∈ {
        algorithm | protocol | certificate | related-crypto-material }
```

`type` is the outer CycloneDX component kind. `assetType` sub-classifies each
`cryptographic-asset` component. Across the full `components` array, the
`cryptographic-asset` bucket holds a mix of all four asset types.

---

## 2. `components[].type` — values `cradar` emits

CycloneDX defines many component types; `cradar` emits exactly **two**:

| `type` | Meaning | Carries `cryptoProperties`? |
|---|---|---|
| `cryptographic-asset` | A discovered cryptographic asset (algorithm, protocol, certificate, key/IV/secret). | ✅ Yes |
| `library` | A cryptographic **library import** (e.g. detecting `import cryptography`, `require('crypto')`). Per [ADR-040](../../decisions/ADR-040-library-asset-type.md), `library` is **not** a valid `cryptoProperties.assetType` value, so library presence is emitted as a plain CycloneDX `library` component with **no** `cryptoProperties`. | ❌ No |

> **Migration note (ADR-040):** if you previously filtered on
> `cryptoProperties.assetType == "library"`, switch to `component.type == "library"`.

### Library identification (`group` / `version` / `purl`)

When a detected crypto library resolves to a concrete dependency in a project
manifest/lockfile, `cradar` emits standard CycloneDX component identity fields:

| Field | Example | Notes |
|---|---|---|
| `name` | `node-forge` | Upgraded to the concrete package name when resolved. |
| `version` | `1.3.1` | From a manifest or lockfile (see manifest sources below). |
| `group` | `org.bouncycastle` | Maven groupId only. |
| `purl` | `pkg:npm/node-forge@1.3.1` | Package URL; version-less (`pkg:npm/node-forge`) when the package is unambiguous but no manifest pin was found. |

The raw detection hint is always available as a `library` property in
`properties[]`, even when no concrete package/version could be resolved.
Supported enrichment ecosystems today: **npm, PyPI, Maven/Gradle, Cargo,
RubyGems, Go modules, Dart/pub**. Composer (PHP) and NuGet (C#) libraries are
detected but do not yet receive `purl`/`version` enrichment. `group`/`version`/
`purl` may also appear on a `cryptographic-asset` component when its detection
carried a library hint (e.g. PHP mcrypt); its `cryptoProperties` are unaffected.

#### Manifest sources (enrichment pass)

`cli/internal/deps` walks the scan root and indexes:

| Ecosystem | Files parsed | Version notes |
|---|---|---|
| npm | `package-lock.json`, `package.json` | Lockfile supplies concrete versions; `package.json` alone only pins exact versions (ranges like `^1.2.3` stay unresolved). |
| PyPI | `requirements.txt`, `poetry.lock`, `Pipfile.lock` | Pinned specs only from `requirements.txt`; lockfiles preferred. |
| Maven | `pom.xml` | Direct `<dependencies>` plus `<dependencyManagement>` fallback in the same POM; `${property}` resolved from local `<properties>`. |
| Gradle | `gradle.lockfile`, `build.gradle(.kts)`, `gradle/libs.versions.toml` | Literal `group:artifact:version` strings and `libs.<alias>` catalog aliases; lockfile wins over catalog when both exist. |
| Cargo | `Cargo.lock` | |
| RubyGems | `Gemfile.lock` | |
| Go | `go.mod` | |
| Dart/pub | `pubspec.lock` | |

Pass-3 (YARA-X binary) library findings carry their own version from the binary
and **skip** manifest enrichment to avoid cross-ecosystem purl mismatches.

### 2.1 Monitored crypto libraries (Pass-2 inventory rules)

Pass-2 OpenGrep rules with `cbom-asset-type: library` detect cryptographic
**library imports** (supply-chain inventory). Algorithm *usage* inside a library
API is a separate `cryptographic-asset` finding from Pass 1 or other Pass-2
rules.

| Language | Libraries monitored (representative) |
|---|---|
| **Java / Kotlin** | Bouncy Castle, JCA/JCE/JSSE, Spring Security Crypto, JJWT, Nimbus JOSE+JWT, Jasypt, Commons Codec, Google Tink, jBCrypt, argon2-jvm |
| **Python** | pyca/cryptography, hashlib, hmac, ssl, PyCryptodome, PyNaCl, PyCrypto (legacy), passlib, PyJWT, python-jose, authlib, bcrypt, argon2-cffi |
| **JavaScript / TypeScript** | Node.js `crypto`, node-forge, jsonwebtoken, bcrypt, argon2, crypto-js, Web Crypto API, jose, @noble/hashes, @noble/curves, @noble/ciphers, libsodium-wrappers, sodium-native |
| **Go** | stdlib `crypto/*`, `golang.org/x/crypto/*` |
| **Rust** | ring, rustls, openssl, aws-lc-rs, p256, ed25519-dalek, x25519-dalek, chacha20poly1305 |
| **C / C++** | OpenSSL headers, libsodium |
| **C#** | `System.Security.Cryptography`, BouncyCastle.NET, Microsoft.IdentityModel.Tokens, jose-jwt |
| **Ruby** | openssl, bcrypt, digest (stdlib), jwt, rbnacl |
| **PHP** | mcrypt (legacy), firebase/php-jwt, defuse/php-encryption |
| **Swift** | CryptoKit, CommonCrypto, Swift Crypto |
| **Dart** | `package:crypto`, PointyCastle, `package:cryptography` |

Stdlib/platform APIs (JCA, Node `crypto`, Go `crypto/*`, Web Crypto) emit
`type: library` findings with **no purl** by design.

Rule source of truth: `scanner/rules/<lang>.yml` (`cbom-*-crypto-library-import`
and related inventory rules). Enrichment tokens: `cli/internal/deps/library_map.go`.

---

## 3. `cryptoProperties.assetType` — the four crypto sub-types

Present only when `type == "cryptographic-asset"`. Exactly four values
(`cli/internal/types/enums.go`), each pairing with one properties block:

| `assetType` | Properties block | What it represents |
|---|---|---|
| `algorithm` | `algorithmProperties` | A cryptographic algorithm in use (AES, RSA, SHA-256, ML-KEM …). |
| `protocol` | `protocolProperties` | A cryptographic protocol (TLS, SSH, IPsec). |
| `certificate` | `certificateProperties` | An X.509 certificate. |
| `related-crypto-material` | `relatedCryptoMaterialProperties` | Keys, IVs, nonces, salts, secrets, digests, signatures. |

### ⚠️ Values are decomposed, not stored as one string

The "human" value you might expect (`"AES-256"`, `"TLS 1.2"`) is **split across fields**,
not stored verbatim:

- `AES-256-GCM` → `name: "AES"`, `algorithmProperties.parameterSetIdentifier: "256"`,
  `algorithmProperties.mode: "gcm"`, `algorithmProperties.primitive: "block-cipher"`.
- `TLS 1.2` → `name: "TLS"`, `protocolProperties.type: "tls"`, `protocolProperties.version: "1.2"`.

To reconstruct a display label, combine `name` with the relevant sub-fields.

---

## 4. Field reference per asset type

### 4.1 `algorithm` → `algorithmProperties`

| Field | Type | Notes |
|---|---|---|
| `primitive` | enum | The cryptographic primitive class. See enum below. |
| `algorithmFamily` | enum | Named family (AES, RSA, ML-KEM …). ~100 values, see below. |
| `parameterSetIdentifier` | string | Key/parameter size, e.g. `"256"`, `"2048"`, `"512"`. |
| `mode` | enum | Block-cipher mode. See enum below. |
| `padding` | enum | Padding scheme. See enum below. |
| `cryptoFunctions` | enum[] | What the algorithm is used for. See enum below. |
| `executionEnvironment` | string | e.g. `software-plain-ram`. |
| `implementationPlatform` | string | e.g. `x86-64`. |
| `certificationLevel` | string[] | e.g. `["fips140-3"]`. |
| `classicalSecurityLevel` | int | Classical security in bits. |
| `nistQuantumSecurityLevel` | int | NIST PQC level 0–5. **Action signal** — see §5. |

**`primitive`** (16 values):
`ae`, `block-cipher`, `stream-cipher`, `hash`, `xof`, `mac`, `kdf`, `kem`, `pke`,
`signature`, `key-agree`, `key-wrap`, `drbg`, `combiner`, `other`, `unknown`

**`mode`** (9 values):
`cbc`, `ecb`, `ccm`, `gcm`, `cfb`, `ofb`, `ctr`, `other`, `unknown`

**`padding`** (7 values):
`pkcs5`, `pkcs7`, `pkcs1v15`, `oaep`, `raw`, `other`, `unknown`

**`cryptoFunctions`** (13 values):
`generate`, `keygen`, `encrypt`, `decrypt`, `digest`, `tag`, `keyderive`, `sign`,
`verify`, `encapsulate`, `decapsulate`, `other`, `unknown`

**`algorithmFamily`** (~100 values, must match the CycloneDX 1.7 `algorithmFamiliesEnum`).
Grouped for readability:

- **Block/stream ciphers:** `AES`, `DES`, `3DES`, `Blowfish`, `Twofish`, `Serpent`,
  `CAMELLIA`, `ARIA`, `SEED`, `SM4`, `IDEA`, `CAST5`, `CAST6`, `RC2`, `RC4`, `RC5`,
  `RC6`, `ChaCha`, `ChaCha20`, `Salsa20`, `RABBIT`, `HC`, `SNOW3G`, `ZUC`, `Skipjack`,
  `CMEA`, `A5/1`, `A5/2`
- **Hashes / XOFs:** `MD2`, `MD4`, `MD5`, `SHA-1`, `SHA-2`, `SHA-3`, `BLAKE2`, `BLAKE3`,
  `RIPEMD`, `Whirlpool`, `SM3`
- **MACs:** `HMAC`, `CMAC`, `KMAC`, `Poly1305`, `SipHash`, `UMAC`
- **Asymmetric (classical):** `RSAES-OAEP`, `RSAES-PKCS1`, `RSASSA-PKCS1`, `RSASSA-PSS`,
  `DSA`, `FFDH`, `ECDSA`, `ECDH`, `ECIES`, `EdDSA`, `ElGamal`, `SM2`, `SM9`, `BLS`,
  `MQV`
- **Post-quantum:** `ML-KEM`, `ML-DSA`, `SLH-DSA`, `BIKE`, `HQC`, `LMS`, `XMSS`
- **KDFs / password hashing:** `HKDF`, `PBKDF1`, `PBKDF2`, `PBES1`, `PBES2`, `PBMAC1`,
  `SP800-108`, `scrypt`, `bcrypt`, `Argon2`
- **DRBGs:** `CTR_DRBG`, `HMAC_DRBG`, `Hash_DRBG`, `Fortuna`
- **Key exchange / PAKE:** `HPKE`, `OPAQUE`, `SPAKE2`, `SPAKE2PLUS`, `SRP`, `J-PAKE`,
  `X3DH`
- **Telecom / 3GPP:** `MILENAGE`, `TUAK`, `3GPP-XOR`, `EAP-AKA`, `EAP-AKA-PRIME`,
  `5G-AKA`, `IKE-PRF`
- **Other:** `GOST`, `Ascon`

### 4.2 `protocol` → `protocolProperties`

| Field | Type | Notes |
|---|---|---|
| `type` | string | Protocol family: `tls`, `ssh`, `ipsec`, `ssl`, `other`. |
| `version` | string | e.g. `"1.0"`, `"1.2"`, `"1.3"`. |
| `cipherSuites` | object[] | Each: `{ name, identifiers[], algorithms[] }` (algorithms are `bom-ref`s to algorithm components). |
| `ikev2TransformTypes` | object[] | IKEv2 transforms `{ type, algorithms[] }` (IPsec only). |
| `cryptoRefArray` | string[] | `bom-ref`s to related crypto components. |

So `TLS 1.2` → `{ name: "TLS", protocolProperties: { type: "tls", version: "1.2" } }`.

### 4.3 `certificate` → `certificateProperties`

| Field | Type | Notes |
|---|---|---|
| `subjectName` | string | e.g. `CN=api.example.com, O=Example Corp`. |
| `issuerName` | string | Issuing CA. |
| `notValidBefore` | RFC3339 | Validity start. |
| `notValidAfter` | RFC3339 | Validity end. **Action signal** (expiry) — see §5. |
| `certificateAlgorithm` | string | e.g. `SHA256withECDSA`. |
| `signatureAlgorithmRef` | string | `bom-ref` to the signature-algorithm component (emitted as a linked `algorithm` component, shared/deduped across certs). |
| `subjectPublicKeyRef` | string | `bom-ref` to the per-cert public-key `related-crypto-material` component (which itself references a public-key `algorithm` component via `algorithmRef`). |
| `certificateFormat` | string | `X.509` for a successfully parsed cert; `DER` for a parsed binary cert; `PEM` when only the PEM block was seen. |
| `certificateExtension` | string | Security-relevant X.509 extensions, `;`-joined: `KeyUsage=...`, `ExtendedKeyUsage=...`, `BasicConstraints=CA:true/false`, `SubjectAltName=...`. |

> **Certificate dependency graph.** A parsed certificate is decomposed into a
> linked graph: the cert component, a (deduplicated) signature-algorithm
> component, a per-cert subject-public-key material component, and a
> (deduplicated) public-key-algorithm component. The edges appear in the
> top-level `dependencies[]` array (`{ ref, dependsOn[] }`). The synthetic
> algorithm components carry quantum posture (`quantumStatus`,
> `nistQuantumSecurityLevel`, `cradar:quantum:*`), so a cert signed with a
> quantum-vulnerable key surfaces its migration priority. Source formats
> covered: PEM (in source), DER (`.der`/`.cer`/`.crt`), PKCS#7 bundles
> (`.p7b`/`.p7c`), and certificates inside keystores (below).

**Extended identity/context metadata (`cradar:cert:*`).** CycloneDX 1.7
`certificateProperties` is a fixed schema, so the extra fields cradar extracts are
surfaced as free-form **component `properties`** (validation-safe) — i.e. on the
component itself (`component.properties[]`), not inside `certificateProperties`. Each
is emitted only when present:

| Property (`cradar:cert:…`) | Description |
|---|---|
| `serialNumber` | Certificate serial number. |
| `sha256Fingerprint` | SHA-256 fingerprint of the DER certificate. |
| `subjectKeyIdentifier` | Subject Key Identifier (SKI) — used for chain linking. |
| `authorityKeyIdentifier` | Authority Key Identifier (AKI) — links to the issuer's SKI. |
| `publicKeyCurve` | Named curve for EC keys (e.g. `P-256`). |
| `publicKeyExponent` | RSA public exponent (e.g. `65537`). |
| `signatureHash` | Hash used in the certificate signature (e.g. `SHA-256`). |
| `selfSigned` | `true` when subject == issuer (self-signed). |
| `version` | X.509 version (e.g. `3`). |
| `validityDays` | Total validity window, in days. |
| `ocspServer` | OCSP responder URL (from Authority Information Access). |
| `caIssuerUrl` | CA Issuers URL (from Authority Information Access). |
| `crlDistributionPoint` | CRL distribution point URL. |
| `policyOid` | Certificate policy OID(s). |

> Material that routes to the cert parser but fails to parse is surfaced as a
> low-severity `cbom-cert-unparsed` finding rather than silently dropped.

### Keystores (JKS / PKCS#12 / JCEKS / BKS / BCFKS / …)

Keystore files are inspected — coverage by format:

| Format | Extensions | Handling |
|---|---|---|
| JKS, PKCS#12 | `.jks` `.keystore` `.truststore` `.p12` `.pfx` `.pkcs12` `.pk12` | certificates enumerated (password-aware) |
| JCEKS | `.jceks` | certificates enumerated (pure-Go; cert entries are plaintext — no password needed) |
| BKS | `.bks` | certificates enumerated (pure-Go; plaintext cert entries) |
| BCFKS, UBER | `.bcfks` `.ubr` `.uber` | **presence-only** — whole store encrypted (needs password + BouncyCastle) |
| macOS Keychain, Mozilla NSS | `.keychain` `.keychain-db`, `cert9.db` / `key4.db` / … | **presence-only** — non-Java formats (NSS matched by exact filename) |

- A `cbom-keystore-present` finding is **always** emitted (path-stamped), noting
  whether the store is locked/unsupported or contains private-key material — so
  even an unparsed store is captured, never invisible.
- Embedded certificates are enumerated and modeled exactly like file
  certificates (the linked graph above).
- For password-protected stores, `cradar` tries a curated set of well-known /
  default passwords (JDK `changeit`, `android`, `notasecret`, WebLogic demo
  stores, common weak values, plus the filename); passwords **harvested** from
  the project's own config keys and keystore-load API calls (coverage-only —
  never logged or reported); and any list passed via `--keystore-wordlist
  <file>`. If a default/weak password opens the store, a
  `cbom-keystore-weak-password` **security** finding (HIGH) is emitted. `cradar`
  never downloads wordlists.

### 4.4 `related-crypto-material` → `relatedCryptoMaterialProperties`

| Field | Type | Notes |
|---|---|---|
| `type` | enum | The material kind. See enum below. |
| `size` | int | Bit size where known. |
| `state` | enum | Lifecycle state: `pre-activation`, `active`, `suspended`, `deactivated`, `compromised`, `destroyed`. |
| `algorithmRef` | string | `bom-ref` to the algorithm this material belongs to. |
| `format` | string | e.g. `PEM`, `raw`. |

**`type`** (21 values):
`private-key`, `public-key`, `secret-key`, `key`, `ciphertext`, `signature`, `digest`,
`initialization-vector`, `nonce`, `seed`, `salt`, `shared-secret`, `tag`,
`additional-data`, `password`, `credential`, `token`, `other`, `unknown`

---

## 5. Which fields signal action?

**`type` and `assetType` are descriptive, not prescriptive.** They tell you *what* an
asset is, not *whether it is a problem*. A plain `algorithm` entry for AES-256-GCM needs
no action — it is healthy inventory.

The **action signal lives in the component's `properties[]` array** (CycloneDX
name/value pairs, emitted by `buildFindingProperties`) and in a few risk-bearing fields:

| Signal | Where | Action |
|---|---|---|
| `severity` = `critical` / `high` | `properties[]` | Security misuse (weak cipher, ECB, hardcoded key/IV, MD5, short RSA key). Triage and remediate. This is what `cradar policy check --fail-on` gates on. |
| `quantumStatus` = `quantum-vulnerable` / `broken` | `properties[]` | Quantum-vulnerable algorithm (RSA/ECC/DH/DSA). Plan PQC migration (NIST IR 8547 — 2030/2035). |
| `cradar:quantum:priority` = `critical` / `high` / `medium` | `properties[]` | HNDL-aware migration urgency. `critical` = broken, **or** quantum-vulnerable key-exchange/encryption (harvest-now-decrypt-later); `high` = quantum-vulnerable signature; `medium` = other vulnerable primitive; `none` = quantum-safe. |
| `cradar:quantum:recommendation` | `properties[]` | Free-text migration guidance for the algorithm. |
| `cradar:quantum:migrationTarget` | `properties[]` | Structured PQC replacement, e.g. `ML-KEM (FIPS 203)` / `ML-DSA (FIPS 204)`. |
| `nistQuantumSecurityLevel` low/`0` | `algorithmProperties` | Same quantum-readiness axis, expressed numerically. |
| `notValidAfter` near/past now | `certificateProperties` | Certificate expiring or expired. Rotate. |
| `state` = `compromised` | `relatedCryptoMaterialProperties` | Key/material flagged compromised. Revoke and re-key. |

`quantumStatus` values: `quantum-safe`, `quantum-vulnerable`, `broken`,
`quantum-unknown`, `not-applicable`. `severity` values: `critical`, `high`, `medium`,
`low`, `info`. The `cradar:quantum:*` properties are emitted only when the
finding has a definitive quantum status (vulnerable / broken / safe).

### Inventory vs action, at a glance

- **Pure inventory** (no action): `type: library`; `cryptographic-asset` entries with no
  high `severity`, `quantumStatus` of `quantum-safe`/`not-applicable`, valid certs.
- **Action candidates:** anything with `severity` ≥ high, `quantumStatus` in
  {`quantum-vulnerable`, `broken`}, an expiring cert, or `state: compromised`.

The cleanest CLI split today is `--only-security` (action candidates by rule category)
vs `--only-inventory` (the descriptive BOM). Note this filters by **rule category**, a
different axis from `assetType` — see §6.

---

## 6. Filtering the output

### By rule category (built-in)

| Flag | Effect |
|---|---|
| `--only-inventory` | Keep inventory-category findings only. |
| `--only-security` | Keep security-category findings only. |
| `--category inventory,security` | Explicit include list. |
| `--disable-rule <id>` | Drop a specific rule. |

These operate on the **rule category** (`inventory` vs `security`), **not** on
`components[].type` or `cryptoProperties.assetType`.

### By asset type (`--asset-type` / `--exclude-type`)

Filter findings by CBOM asset type directly, without post-processing. Both flags
are repeatable; `--exclude-type` is applied after `--asset-type`. Valid values:
`algorithm`, `protocol`, `certificate`, `related-crypto-material`, `library`.

```bash
# Only algorithm components
cradar scan ./app --asset-type algorithm -o cbom.json

# Everything except crypto-library imports
cradar scan ./app --exclude-type library -o cbom.json
```

The same shaping is still available with `jq` if you prefer to post-filter:

```bash
# Only algorithm components
jq '[.components[] | select(.cryptoProperties.assetType == "algorithm")]' cbom.json

# Drop crypto-library imports
jq '.components |= map(select(.type != "library"))' cbom.json

# Only certificates expiring before a date
jq --arg d "2026-01-01T00:00:00Z" \
   '[.components[] | select(.cryptoProperties.assetType=="certificate"
     and .cryptoProperties.certificateProperties.notValidAfter < $d)]' cbom.json

# Only quantum-vulnerable algorithms
jq '[.components[] | select(any(.properties[]?;
     .name=="quantumStatus" and .value=="quantum-vulnerable"))]' cbom.json
```

---

## 7. Source of truth

| Enum | File |
|---|---|
| `assetType` values | `cli/internal/types/enums.go` |
| `primitive`, `mode`, `padding`, `cryptoFunctions`, `algorithmFamily`, related-material `type`/`state` | `cli/internal/cyclonedx17/enums.go` |
| `severity`, `confidence`, `quantumStatus` | `cli/internal/types/enums.go` |
| Component-type routing (`library` vs `cryptographic-asset`) | `cli/internal/output/converter.go`, [ADR-040](../../decisions/ADR-040-library-asset-type.md) |
| Property-bag (`severity`/`quantumStatus`/`fingerprint`) emission | `cli/internal/output/converter.go` (`buildFindingProperties`) |

See also: [output-formats.md](output-formats.md) for the list of writers, and
[ADR-001](../../decisions/ADR-001-output-format.md) for why CycloneDX 1.7.
