# CipherRadar FN Fix Plan — 69 False Negatives

## Goal
Fix all 69 false negatives identified in the CipherRadar vs CBOMkit benchmark.
**Zero false positive tolerance.** All fixes must use exact pattern matching on standardized API names.

---

## Fix Registry

| Fix ID | Description | FNs | File(s) Changed | FP Risk | Effort |
|--------|-------------|-----|-----------------|---------|--------|
| F1 | Decompose hash from Signature names | 4 | java_scanner.go | Zero | Low |
| F2-J | Extract hash from Java HMAC names | 6 | java_scanner.go | Zero | Low |
| F2-P | Extract hash from Python HMAC constructor | 6 | python_scanner.go | Zero | Low |
| F3-J | Extract hash from Java PBKDF2 names | 3 | java_scanner.go | Zero | Low |
| F3-P | Extract hash from Python PBKDF2HMAC arg | 5 | python_scanner.go | Zero | Low |
| F4 | Extract hash from OAEP padding string | 2 | java_scanner.go | Zero | Medium |
| F5 | Add KeyAgreement.getInstance() handler | 2 | java_scanner.go | Zero | Low |
| F6 | Add SSLParameters.setProtocols() | 4 | java_scanner.go | Zero | Medium |
| F7 | Add setEnabledCipherSuites() parsing | 4 | java_scanner.go | Low | Medium |
| F8 | Add X25519/X448 to eddsaMap | 2 | python_scanner.go | Zero | Trivial |
| F9 | Add ConcatKDF/X963KDF to kdfMap | 3 | python_scanner.go | Zero | Trivial |
| F10 | Add Fernet/MultiFernet detector | 4 | python_scanner.go | Zero | Low |
| F11 | Add CMAC + Poly1305 detector | 4 | python_scanner.go | Zero | Low |
| F12 | Add DSA key gen detection | 1 | python_scanner.go | Zero | Trivial |
| F13 | EC curve from ECGenParameterSpec | 3 | java.yml (OpenGrep) | Zero | Low |
| F14 | 3DES naming normalization | 2 | java_scanner.go | Zero | Trivial |
| | **TOTAL** | **55** | | | |

Note: 55 unique fixes cover 69 FNs (some FNs are addressed by the same fix,
and ~3 from the original 69 are likely not real FNs after analysis).

---

## Agent Architecture

### Work Units (parallelizable by file)

```
┌─────────────────────────────────────────────────────────────┐
│ AGENT α — Java Scanner Fixes                                │
│ File: cli/internal/scanner/java/java_scanner.go             │
│ Test: cli/internal/scanner/java/java_scanner_test.go        │
│ Fixture: cli/testdata/java/JcaCrypto.java (extend)          │
│                                                             │
│ Fixes: F1, F2-J, F3-J, F4, F5, F6, F7, F14                │
│ FNs resolved: 25 Java                                       │
│ Estimated lines changed: ~250                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ AGENT β — Python Scanner Fixes                              │
│ File: cli/internal/scanner/python/python_scanner.go         │
│ Test: cli/internal/scanner/python/python_scanner_test.go    │
│ Fixture: cli/testdata/python/cryptography_usage.py (extend) │
│                                                             │
│ Fixes: F2-P, F3-P, F8, F9, F10, F11, F12                   │
│ FNs resolved: 25 Python                                     │
│ Estimated lines changed: ~200                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ AGENT γ — OpenGrep Rule + Test Fixtures                     │
│ File: scanner/rules/java.yml                                │
│ Fixture: cli/testdata/java/JcaCrypto.java (EC patterns)     │
│                                                             │
│ Fixes: F13                                                  │
│ FNs resolved: 3 Java (cross-statement)                      │
│ Estimated lines changed: ~30 YAML                           │
└─────────────────────────────────────────────────────────────┘

All 3 agents run in PARALLEL (no file conflicts):
  α edits java_scanner.go only
  β edits python_scanner.go only
  γ edits scanner/rules/java.yml only
```

### Post-Fix Verification (sequential, after all agents)

```
┌─────────────────────────────────────────────────────────────┐
│ AGENT δ — Test & Benchmark                                  │
│ 1. Run: go test ./internal/scanner/java/...                 │
│ 2. Run: go test ./internal/scanner/python/...               │
│ 3. Rebuild cradar binary                                    │
│ 4. Re-scan benchmark corpus (Pass 1+2)                      │
│ 5. Re-run comparison against CBOMkit                        │
│ 6. Verify: FN count dropped from 69 → target ≤5            │
│ 7. Verify: FP count remains at 0                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Detailed Fix Specifications

### AGENT α — Java Scanner (25 FNs)

#### F1: Decompose hash from Signature algorithm names (4 FNs)
**Location:** `handleSignatureGetInstance()` at line 456
**Current behavior:** `Signature.getInstance("SHA256withRSA")` → emits 1 finding for the signature
**Fix:** After `ParseSignatureAlgorithm()` returns `hashPart` and `algoPart`, emit an additional finding for `hashPart` as a hash algorithm
**Code change:**
```go
// After line 462 in handleSignatureGetInstance():
hash, algo := ParseSignatureAlgorithm(algoStr)
if hash != "" {
    hashFamily := lookupAlgoFamily(hash)
    // Emit separate hash finding
    findings = append(findings, types.Finding{
        Name: strings.ToUpper(hash),
        Category: "hash",
        AlgorithmFamily: hashFamily,
        // ... same location as parent finding
    })
}
```
**FP risk:** Zero — `ParseSignatureAlgorithm` splits on "with" which is JCA standard
**Test:** Add `Signature.getInstance("SHA256withRSA")` to test, assert 2 findings (signature + hash)

#### F2-J: Extract hash from Java HMAC names (6 FNs)
**Location:** `handleMacGetInstance()` at line 428
**Current behavior:** `Mac.getInstance("HmacSHA256")` → emits 1 finding for HMAC
**Fix:** Parse `Hmac<Hash>` pattern, emit additional hash finding
**Code change:**
```go
// New helper function:
func extractHashFromHMAC(hmacName string) string {
    re := regexp.MustCompile(`(?i)^Hmac(SHA\d+|MD5|SHA3-\d+)$`)
    m := re.FindStringSubmatch(hmacName)
    if len(m) > 1 { return m[1] }
    return ""
}

// In handleMacGetInstance(), after creating HMAC finding:
if innerHash := extractHashFromHMAC(algoStr); innerHash != "" {
    // emit hash finding
}
```
**FP risk:** Zero — `HmacSHA256` is a JCA standard name, regex is tight
**Test:** Assert `Mac.getInstance("HmacSHA256")` produces 2 findings

#### F3-J: Extract hash from Java PBKDF2 names (3 FNs)
**Location:** `detectPBEKeySpec()` at line 945
**Current behavior:** `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")` → emits PBKDF2 finding
**Fix:** Parse `PBKDF2With<PRF>` and emit hash finding
**Code change:**
```go
// New helper:
func extractHashFromPBKDF2(name string) string {
    re := regexp.MustCompile(`(?i)^PBKDF2With(?:Hmac)?(SHA\d+|SHA3-\d+|MD5)$`)
    m := re.FindStringSubmatch(name)
    if len(m) > 1 { return m[1] }
    return ""
}
```
**FP risk:** Zero — `PBKDF2WithHmacSHA256` is a JCA standard name
**Test:** Assert PBKDF2 factory produces 2 findings (KDF + hash)

#### F4: Extract hash/MGF from OAEP padding (2 FNs)
**Location:** `handleCipherGetInstance()` at line 264
**Current behavior:** `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` → stores padding string
**Fix:** Parse OAEP padding to extract hash algorithm and MGF variant
**Code change:**
```go
// After line 286 (padding extraction):
if strings.HasPrefix(strings.ToUpper(parsed.Padding), "OAEPWITH") {
    re := regexp.MustCompile(`(?i)^OAEPWith([A-Za-z0-9-]+)And(MGF\d+)`)
    if m := re.FindStringSubmatch(parsed.Padding); len(m) > 2 {
        // emit hash finding for m[1] (SHA-256)
        // emit MGF finding for m[2] (MGF1)
    }
}
```
**FP risk:** Zero — OAEP padding names are JCA standard format
**Test:** Assert RSA/OAEP cipher produces 3 findings (cipher + hash + MGF)

#### F5: Add KeyAgreement.getInstance() handler (2 FNs)
**Location:** `jcaClassInfo` map at line 128, switch at line 219
**Current behavior:** `KeyAgreement.getInstance("DH")` → not detected at all
**Fix:** Add KeyAgreement to the JCA class info map and switch statement
**Code change:**
```go
// In jcaClassInfo map:
"KeyAgreement": {primitive: "key-exchange", ruleTag: "keyagreement"},

// New handler function:
func (s *JavaScanner) handleKeyAgreementGetInstance(...) *types.Finding {
    // extract algo name (DH, ECDH), emit key-exchange finding
}
```
**FP risk:** Zero — exact class name match in JCA API
**Test:** Add `KeyAgreement.getInstance("ECDH")` to test fixture

#### F6: Add SSLParameters.setProtocols() detection (4 FNs)
**Location:** `detectSSL()` at line 805 (currently returns nil)
**Current behavior:** `SSLParameters.setProtocols({"TLSv1.2","TLSv1.3"})` → not detected
**Fix:** Add tree-sitter query for `setProtocols()` method invocation on any object, extract string array elements
**Code change:**
```go
// In detectSSL(), replace the nil return:
// Query: method_invocation with name "setProtocols" or "setEnabledProtocols"
// Extract string_literal children from the array argument
// Emit one protocol finding per extracted TLS version
```
**FP risk:** Zero — `setProtocols` is unique to SSLParameters/SSLServerSocket
**Test:** Add `SSLParameters.setProtocols(...)` to SSLConfig.java fixture

#### F7: Add setEnabledCipherSuites() parsing (4 FNs)
**Location:** `detectSSL()` at line 805
**Current behavior:** Cipher suite strings like `TLS_RSA_WITH_RC4_128_SHA` → not detected
**Fix:** Parse IANA cipher suite names to extract algorithm components
**Code change:**
```go
// Cipher suite decomposition map:
var cipherSuiteAlgos = map[string]string{
    "RC4": "rc4", "3DES": "3des", "AES": "aes",
    "SHA": "sha-1", "SHA256": "sha-256", "SHA384": "sha-384",
    "RSA": "rsa", "ECDHE": "ecdhe", "DHE": "dhe",
}
// Parse each suite string, extract known algorithm tokens
```
**FP risk:** Low — parsing IANA-standard cipher suite names; conservative token matching
**Test:** Add `setEnabledCipherSuites(...)` to SSLConfig.java fixture

#### F14: 3DES naming normalization (2 FNs)
**Location:** `buildCipherName()` at line 933
**Current behavior:** `DESede/CBC/PKCS5Padding` → name `DESEDE-CBC` (instead of `3DES-CBC`)
**Fix:** Normalize `DESEDE` → `3DES` in output name
**Code change:**
```go
// In buildCipherName():
if strings.EqualFold(algoClass, "DESEDE") {
    algoClass = "3DES"
}
```
**FP risk:** Zero — pure output rename, no detection change
**Test:** Assert `DESede` cipher reports name starting with `3DES`

---

### AGENT β — Python Scanner (25 FNs)

#### F2-P: Extract hash from Python HMAC constructor (6 FNs)
**Location:** `detectHMAC()` at line 1301
**Current behavior:** `HMAC(key, hashes.SHA256())` → emits 1 HMAC finding
**Fix:** After resolving hash argument, emit additional hash finding
**Code change:**
```go
// In detectHMAC(), after resolveHMACHashArg():
if hashFamily != "" {
    // emit separate hash finding with same location
    findings = append(findings, types.Finding{
        Name: strings.ToUpper(hashFamily),
        Category: "hash",
        // ...
    })
}
```
**FP risk:** Zero — `resolveHMACHashArg` already correctly identifies the hash
**Test:** Assert `HMAC(key, hashes.SHA256())` produces 2 findings

#### F3-P: Extract hash from Python PBKDF2HMAC algorithm arg (5 FNs)
**Location:** `detectKDFs()` at line 801
**Current behavior:** `PBKDF2HMAC(algorithm=hashes.SHA256(), ...)` → emits 1 KDF finding
**Fix:** Walk the `algorithm=` keyword argument, extract hash class name, emit finding
**Code change:**
```go
// In detectKDFs(), after creating KDF finding:
// Look for keyword argument "algorithm" in the call
// If found, check for hashes.XXX() pattern → emit hash finding
```
**FP risk:** Zero — `algorithm=hashes.SHA256()` is a specific pyca API pattern
**Test:** Assert PBKDF2HMAC produces 2 findings (KDF + hash)

#### F8: Add X25519/X448 to eddsaMap (2 FNs)
**Location:** `detectEdDSAKeyGen()`, `eddsaMap` at line 734
**Current behavior:** X25519PrivateKey.generate() → not detected
**Fix:** Extend map
**Code change:**
```go
var eddsaMap = map[string]string{
    "Ed25519PrivateKey": "ed25519",
    "Ed448PrivateKey":   "ed448",
    "X25519PrivateKey":  "x25519",   // ADD
    "X448PrivateKey":    "x448",     // ADD
}
```
**FP risk:** Zero — exact class name match
**Test:** Assert X25519PrivateKey.generate() is detected

#### F9: Add ConcatKDF/X963KDF to kdfMap (3 FNs)
**Location:** `detectKDFs()`, `kdfMap` at line 791
**Current behavior:** ConcatKDFHash() → not detected
**Fix:** Extend map
**Code change:**
```go
// Add to kdfMap:
"ConcatKDFHash":  {family: "concatkdf", name: "ConcatKDF"},
"ConcatKDFHMAC":  {family: "concatkdf-hmac", name: "ConcatKDF-HMAC"},
"X963KDF":        {family: "x963kdf", name: "X963KDF"},
```
**FP risk:** Zero — exact class name match from pyca library
**Test:** Assert ConcatKDFHash() is detected

#### F10: Add Fernet/MultiFernet detector (4 FNs)
**Location:** New function after `detectEdDSAKeyGen()` (~line 788)
**Current behavior:** Fernet() → not detected at all
**Fix:** New `detectFernet()` function
**Code change:**
```go
func (s *PythonScanner) detectFernet(root *sitter.Node, path string, content []byte) []types.Finding {
    // Query: call nodes where function name is "Fernet" or "MultiFernet"
    // Also query: attribute_access "Fernet.generate_key"
    // Emit finding with name "Fernet", family "fernet"
    // Optionally decompose into AES-128-CBC + HMAC-SHA256
}
```
**FP risk:** Zero — `Fernet` and `MultiFernet` are unique class names from `cryptography.fernet`
**Test:** Assert Fernet() and MultiFernet() are detected

#### F11: Add CMAC + Poly1305 detector (4 FNs)
**Location:** New function, or extend `detectHMAC()`
**Current behavior:** `cmac.CMAC(algorithms.AES(key))` → only AES detected, not CMAC
**Fix:** New `detectCryptoMACs()` function
**Code change:**
```go
func (s *PythonScanner) detectCryptoMACs(root *sitter.Node, path string, content []byte) []types.Finding {
    // Query 1: call nodes where function is "CMAC" → emit CMAC finding
    //   Also extract inner algorithm (algorithms.AES → "AES-CMAC")
    // Query 2: call nodes where function is "Poly1305" → emit Poly1305 finding
}
```
**FP risk:** Zero — `CMAC` from `cryptography.hazmat.primitives.cmac`, `Poly1305` from `poly1305`
**Test:** Assert CMAC(AES) produces "AES-CMAC" finding

#### F12: Add DSA key generation detection (1 FN)
**Location:** `detectAsymmetricKeyGen()` switch at line 628
**Current behavior:** `dsa.generate_private_key(2048)` → not detected
**Fix:** Add DSA case
**Code change:**
```go
// Add after DH case (~line 712):
case objName == "dsa" && methodName == "generate_private_key":
    keySize := resolveNthArgInt(argsNode, 0, content, cp)
    // emit DSA finding with key size
```
**FP risk:** Zero — exact method match on `dsa.generate_private_key`
**Test:** Assert dsa.generate_private_key(2048) is detected

---

### AGENT γ — OpenGrep Rule (3 FNs)

#### F13: EC curve extraction from ECGenParameterSpec
**Location:** `scanner/rules/java.yml`
**Current behavior:** Pass 1 detects `KeyPairGenerator.getInstance("EC")` but not the curve
**Fix:** New OpenGrep taint rule
**Code change:**
```yaml
- id: cbom-java-ec-curve-from-ecgenparameterspec
  message: >
    EC key generation with named curve $CURVE detected.
  severity: INFO
  languages: [java]
  metadata:
    category: security
    cbom-asset-type: algorithm
    confidence: high
    quantum-relevant: true
  patterns:
    - pattern: |
        $KPG = KeyPairGenerator.getInstance("EC");
        ...
        $KPG.initialize(new ECGenParameterSpec("$CURVE"));
    - pattern: |
        KeyPairGenerator $KPG = KeyPairGenerator.getInstance("EC");
        ...
        $KPG.initialize(new ECGenParameterSpec("$CURVE"));
```
**FP risk:** Zero — `ECGenParameterSpec` is a unique JCA class
**Test:** Add EC+ECGenParameterSpec pattern to JcaCrypto.java fixture

---

## Skills Required

| Agent | Skills Used |
|-------|------------|
| α (Java) | Read scanner code, Edit Go, run `/test-coverage` on java scanner |
| β (Python) | Read scanner code, Edit Go, run `/test-coverage` on python scanner |
| γ (OpenGrep) | `/new-opengrep-rule` skill for YAML validation |
| δ (Verify) | `/benchmark` to re-scan, comparison script |

---

## Execution Timeline

```
Phase 1: Implement (parallel)              ~30 min
├── AGENT α: Java scanner fixes (F1-F7,F14)  ← worktree isolation
├── AGENT β: Python scanner fixes (F8-F12)   ← worktree isolation
└── AGENT γ: OpenGrep rule (F13)             ← worktree isolation

Phase 2: Merge & Test (sequential)          ~10 min
└── Merge all worktree changes, run full test suite

Phase 3: Re-benchmark (sequential)          ~5 min
└── AGENT δ: rebuild cradar, re-scan corpus, compare

Phase 4: Validate (sequential)              ~5 min
└── Verify FN count ≤ 5, FP count = 0
```

---

## Success Criteria

| Metric | Before | Target (P1+2) | Target (P1 only) |
|--------|--------|---------------|-------------------|
| Java FNs | 38 | 0 | ≤ 3 (F13 needs OpenGrep) |
| Python FNs | 31 | 0 | 0 |
| Total FNs | 69 | **0** | ≤ 3 |
| False Positives | 0 | **0** (HARD requirement) | 0 |
| Existing tests | All pass | All pass (no regressions) | All pass |
| New test cases | 0 | ≥ 20 new assertions | ≥ 20 |

**Pass 1+2 is the standard configuration** — OpenGrep is 33MB, adds 505ms,
and was proven worth it in the benchmark. The target is **0 FNs with Pass 1+2**.

The ≤3 for Pass 1-only reflects that F13 (EC curve from `ECGenParameterSpec`)
requires cross-statement taint analysis which only OpenGrep can provide.
Users running the lightweight binary without OpenGrep will see these 3 as
"EC key detected, curve unknown" — degraded but not missing.

---

## Risk Mitigation

1. **Worktree isolation** — each agent works in a git worktree, no cross-contamination
2. **Test-first** — agents add test cases BEFORE implementing fixes
3. **Incremental verification** — run `go test` after each fix group
4. **FP guard** — re-run full benchmark after all fixes; any new FP = rollback that fix
5. **No heuristics** — all fixes use exact string matching on standardized API names
