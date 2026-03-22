# OpenGrep CBOM Inventory Rules — Implementation Plan

## Goal
Add 13 OpenGrep taint rules for CBOM inventory detection (not vulnerability detection).
These rules capture cross-statement crypto patterns that Pass 1 tree-sitter cannot.

## Current State
- 41 rules across 12 languages (all vulnerability-focused)
- Pass 1 handles single-statement API detection
- Pass 2 only flags bad practices, not crypto inventory

## After Implementation
- 54+ rules (41 existing + 13 new CBOM inventory rules)
- Pass 2 contributes to crypto asset inventory, not just security findings

---

## Phase 1 — Tier 1: Highest ROI, Zero-to-Low FP Risk

### Rule 1: Crypto Library Imports (all languages)
```
ID pattern: cbom-<lang>-crypto-library-import
Asset type: library
Languages: All 12
```
Detects: Import/require statements for crypto libraries.
Examples:
- Java: `import org.bouncycastle.*`, `import javax.crypto.*`
- Python: `from cryptography import *`, `import hashlib`, `from Crypto import *`
- Go: `"crypto/aes"`, `"golang.org/x/crypto/*"`
- JS: `require('crypto')`, `import forge from 'node-forge'`
- Rust: `use ring::*`, `use rustls::*`
- C#: `using System.Security.Cryptography`
- PHP: `use phpseclib\Crypt\*`
- Ruby: `require 'openssl'`, `require 'bcrypt'`

### Rule 2: Deprecated Library Imports (PHP, Python, Ruby, JS)
```
ID pattern: cbom-<lang>-deprecated-crypto-import
Asset type: library
Languages: PHP, Python, Ruby, JS
```
Detects:
- PHP: `mcrypt_*` function calls (deprecated since PHP 7.1)
- Python: `from Crypto import *` (old PyCrypto, replaced by PyCryptodome)
- Ruby: `require 'digest/crc32'` or other weak digest imports
- JS: `require('crypto-js')` (often misused)

### Rule 3: KDF → Derived Key → Cipher Chain (Java, Python, Go)
```
ID pattern: cbom-<lang>-kdf-to-cipher-chain
Asset type: key-derivation-function
Languages: Java, Python, Go
```
Detects: Password → KDF → derived key → cipher initialization
Examples:
- Java: `SecretKeyFactory.getInstance("PBKDF2...").generateSecret(spec)` → key → `Cipher.init()`
- Python: `PBKDF2HMAC(...).derive(password)` → key → `Cipher(algorithms.AES(key), ...)`
- Go: `scrypt.Key(password, salt, ...)` → key → `aes.NewCipher(key)`

### Rule 4: TLS Version Pinning (Java, Python, Go)
```
ID pattern: cbom-<lang>-tls-version-pin
Asset type: protocol
Languages: Java, Python, Go
```
Detects: Explicit TLS version enforcement
Examples:
- Java: `SSLContext.getInstance("TLSv1.3")` → `ctx.init(...)` → `setEnabledProtocols({"TLSv1.3"})`
- Python: `ctx.minimum_version = ssl.TLSVersion.TLSv1_3`
- Go: `tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}`

---

## Phase 2 — Tier 2: Medium ROI

### Rule 5: Key Generator → Cipher Usage (Java, C#)
```
ID: cbom-<lang>-keygen-to-cipher
Asset type: related-crypto-material
```
Detects: `KeyGenerator.generateKey()` → variable → `Cipher.init(mode, key)`

### Rule 6: Config-Driven Algorithm Selection (Java, Python, Go, JS)
```
ID: cbom-<lang>-config-driven-algorithm
Asset type: algorithm
```
Detects: Algorithm string read from Properties/env/config → passed to crypto API

### Rule 7: Cipher Suite Enumeration (Java, Python, Go)
```
ID: cbom-<lang>-cipher-suite-inventory
Asset type: protocol
```
Detects: Specific cipher suites enabled in TLS context configuration

### Rule 8: Certificate Load → TLS Context (Java, Python)
```
ID: cbom-<lang>-cert-to-tls-context
Asset type: certificate
```
Detects: Certificate file loaded → used in SSLContext/ssl.SSLContext

### Rule 9: Crypto Provider Registration (Java)
```
ID: cbom-java-crypto-provider-registration
Asset type: library
```
Detects: `Security.addProvider(new BouncyCastleProvider())` etc.

---

## Phase 3 — Tier 3: Specialized

### Rule 10: Wrapper Function Detection (Java, Python)
```
ID: cbom-<lang>-crypto-wrapper-function
Asset type: algorithm
```
Detects: Internal functions that wrap standard crypto APIs

### Rule 11: EC Curve from Configuration (Java, Go)
```
ID: cbom-<lang>-ec-curve-from-config
Asset type: algorithm
```
Detects: EC curve name from config/env → ECGenParameterSpec / elliptic.P256()

### Rule 12: Certificate Validation Chain (Java, Python)
```
ID: cbom-<lang>-cert-validation-chain
Asset type: certificate
```
Detects: cert.checkValidity() + cert.verify() multi-statement flow

### Rule 13: bcrypt/scrypt Inventory (Python, Go, Rust)
```
ID: cbom-<lang>-password-hash-inventory
Asset type: algorithm
```
Detects: Password hashing in auth context with cost/work factor extraction

---

## Agent Architecture

### Work Units (parallelizable by language group)

```
┌───────────────────────────────────────────────────────────┐
│ AGENT A — Java + Kotlin Rules                             │
│ Files: scanner/rules/java.yml, scanner/rules/kotlin.yml   │
│ Rules: 1,2,3,4,5,6,7,8,9,10,11,12 (Java-applicable)      │
│ Skill: /opengrep-cbom-java                                │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│ AGENT B — Python Rules                                    │
│ Files: scanner/rules/python.yml                           │
│ Rules: 1,2,3,4,6,7,8,10,12,13                            │
│ Skill: /opengrep-cbom-python                              │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│ AGENT C — Go + JavaScript + TypeScript Rules              │
│ Files: scanner/rules/go.yml, scanner/rules/javascript.yml │
│ Rules: 1,3,4,6,7,11,13                                   │
│ Skill: /opengrep-cbom-jsgo                                │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│ AGENT D — C#, PHP, Ruby, Rust, Swift, Dart, C++ Rules     │
│ Files: 7 rule files                                       │
│ Rules: 1,2,13 (language-specific subsets)                  │
│ Skill: /opengrep-cbom-multi                               │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│ AGENT E — Verification (after all agents)                 │
│ Validates YAML, runs scans, measures improvement          │
│ Skill: /opengrep-cbom-verify                              │
└───────────────────────────────────────────────────────────┘

All 4 implementation agents run in PARALLEL (no file conflicts).
Agent E runs SEQUENTIALLY after all complete.
```

---

## Execution Timeline

```
Wave 1: All phases, all agents in parallel     ~20 min
├── AGENT A: Java + Kotlin (12 rules)
├── AGENT B: Python (10 rules)
├── AGENT C: Go + JS (7 rules)
└── AGENT D: C#/PHP/Ruby/Rust/Swift/Dart/C++ (7+ rules)

Wave 2: Verification                            ~5 min
└── AGENT E: YAML validate + scan + measure

Wave 3: Commit + push                           ~2 min
```

---

## Success Criteria

| Metric | Before | Target |
|--------|--------|--------|
| Total OpenGrep rules | 41 | 54+ |
| CBOM inventory rules | 0 | 13+ |
| YAML validation | All pass | All pass |
| Existing tests | All pass | All pass (no regressions) |
| FPs introduced | 0 | 0 |
