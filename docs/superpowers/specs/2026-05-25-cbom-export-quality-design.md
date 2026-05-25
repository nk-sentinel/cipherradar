# CBOM Export Quality — Design

**Date:** 2026-05-25
**Branch:** `feature/cbom-export-quality`
**Owner:** nk-sentinel
**Status:** Approved

## Goal

Improve the correctness, completeness, and reporting quality of `cradar`'s CBOM output along three axes:

1. **Validation correctness** — CBOM JSON output must conform to the CycloneDX 1.7 schema. Today it emits invented enum values that fail `cradar scan --validate`.
2. **Quantum readiness coverage** — the `quantum.go` table covers only ~30 algorithm families. Common classical algorithms (HMAC, Poly1305, ElGamal, ECIES, KDFs, password hashers) and PQC aliases (Kyber→ML-KEM, Dilithium→ML-DSA, SPHINCS+→SLH-DSA) are classified as "Unknown". Non-algorithm asset types (hardcoded secrets, certificates) are wrongly bucketed into the quantum readiness lookup.
3. **PDF report depth** — the inventory summary currently shows only severity + quantum counts. Operators want breakdowns by `assetType`, `primitive`, top-N algorithms, per-language distribution, compliance status, and a quantum migration backlog table. A `--baseline` diff would show changes vs. a previous scan.

## Out of scope

- `cfg.Format` wiring (dead config field — separate item)
- The original `feature/cli-improvements` work items: rule-lifecycle metadata, structured logging, multi-output format, shell completion, `cradar init`
- Any portal/backend/frontend changes
- Backwards-compat shims for invalid `assetType: "library"` or `primitive: "HARDCODE-SECRET"` (these were never valid CycloneDX, breaking change in CHANGELOG)

## Architecture overview

One feature branch, three sequential commits, single PR.

**Data flow (after):**
```
Scanner → Finding → converter.go ──▶ normalize/   ──▶ CycloneDX struct ──▶ JSON / SARIF
                                  ↘ (warn or fail per --strict-validate)        ↘ PDF (Option D)
                                                                                    ├── summary aggregator
                                                                                    ├── quantum aggregator (expanded YAML table)
                                                                                    ├── chart renderer (go-echarts SVG)
                                                                                    ├── compliance section
                                                                                    └── baseline diff (reuses cradar diff)
```

**New packages and file moves:**
- `cli/internal/cyclonedx17/normalize/` — pure functions for enum closed-set validation + asset-type rerouting (new package)
- `cli/internal/scanner/quantum/quantum-readiness.yml` — embedded data file via `//go:embed` (new; lives next to `quantum.go` per CLAUDE.md "Quantum algorithm table lives in cli/internal/scanner/quantum/")
- `cli/internal/output/pdf/` — split current 732-line `pdf.go` into focused files

**Boundaries (single-purpose, testable in isolation):**
- Scanners do not know about CycloneDX enums.
- `normalize/` is the only place that knows the CycloneDX 1.7 valid value sets.
- PDF aggregators read from the already-normalized CycloneDX struct, not raw scanner output.

## Work item 1 — Validation fix

### Normalization package

New: `cli/internal/cyclonedx17/normalize/`

```go
package normalize

var (
    AssetTypes        = set{"algorithm", "certificate", "protocol", "related-crypto-material"}
    Primitives        = set{"drbg","mac","block-cipher","stream-cipher","signature","hash","pke","xof","kdf","key-agree","kem","ae","combiner","key-wrap","other","unknown"}
    Modes             = set{"cbc","ecb","ccm","gcm","cfb","ofb","ctr","other","unknown"}
    Paddings          = set{"pkcs5","pkcs7","pkcs1v15","oaep","raw","other","unknown"}
    CryptoFunctions   = set{"generate","keygen","encrypt","decrypt","digest","tag","keyderive","sign","verify","encapsulate","decapsulate","other","unknown"}
    ExecutionEnvs     = set{"software-plain-ram","software-encrypted-ram","software-tee","hardware","other","unknown"}
    ImplPlatforms     = set{"generic","x86_32","x86_64","armv7-a","armv7-m","armv8-a","armv8-m","armv9-a","armv9-m","s390x","ppc64","ppc64le","other","unknown"}
    AlgorithmFamilies = set{ /* 95 values from cryptography-defs.schema.json */ }
)

var primitiveAliases = map[string]string{
    "block_cipher": "block-cipher", "blockcipher": "block-cipher",
    "stream_cipher": "stream-cipher",
    "key-derivation": "kdf", "keyderivation": "kdf",
    "key-agreement": "key-agree", "keyagreement": "key-agree",
    "cipher-suite": "other",
    // full map populated during implementation per scan of current scanner output
}

var algorithmFamilyAliases = map[string]string{
    "concatkdf": "HKDF", "concatkdf-hmac": "HKDF", "x963kdf": "HKDF",
    "fernet": "AES", "poly1305": "Poly1305",
    "aes-cmac": "CMAC", "3des-cmac": "CMAC",
    // covers the 37 documented in TODO-SCHEMA-VALIDATION.md (to be deleted at end of commit 1)
}

func Primitive(v string) (string, bool)        // (normalized, wasValid)
func AssetType(v string) (string, bool)
func AlgorithmFamily(v string) (string, bool)
// ... one per enum
```

### Asset rerouting

In `converter.go`, before emitting `cryptoProperties`:

```go
func rerouteAssetType(f types.Finding) (assetType string, props *CryptoProps) {
    name := strings.ToLower(f.Name)
    switch {
    case strings.Contains(name, "secret") || strings.Contains(name, "hardcoded-key") || strings.Contains(name, "api-key"):
        return "related-crypto-material", buildRelatedMaterial(f, "secret-parameter")
    case strings.Contains(name, "certificate") || strings.HasSuffix(f.Location.File, ".pem") || strings.HasSuffix(f.Location.File, ".crt"):
        return "certificate", buildCertificate(f)
    case strings.Contains(name, "private-key") || strings.HasSuffix(f.Location.File, ".key"):
        return "related-crypto-material", buildRelatedMaterial(f, "private-key")
    default:
        return "algorithm", buildAlgorithm(f)
    }
}
```

`relatedCryptoMaterialProperties.type` enum (CycloneDX 1.7): `private-key`, `public-key`, `secret-key`, `key`, `ciphertext`, `signature`, `digest`, `initialization-vector`, `nonce`, `seed`, `salt`, `shared-secret`, `tag`, `additional-data`, `password`, `credential`, `token`, `secret-parameter`, `other`, `unknown`.

### Strictness mode

```go
if cfg.StrictValidate && tally.Total > 0 {
    return nil, fmt.Errorf("strict validation failed: %d normalized values had no valid CycloneDX mapping; see logs", tally.Total)
}
// Default: log each violation as a structured warning to stderr.
```

### Files touched (commit 1)

- **New:** `cli/internal/cyclonedx17/normalize/{normalize.go, normalize_test.go, aliases.go}`
- **New:** `cli/internal/cyclonedx17/normalize/golden/` — testdata with intentionally-broken Finding inputs and expected normalized output
- **Modified:** `cli/internal/output/converter.go` — call normalize, add rerouting
- **Modified:** `cli/internal/cmd/scan.go` — add `--strict-validate` flag
- **Modified:** `cli/internal/scanner/{java,python}/...` — remove invented enum values at source (emit secrets without setting `primitive`)
- **Deleted:** `docs/benchmark/TODO-SCHEMA-VALIDATION.md` (PR description notes why)

## Work item 2 — Quantum readiness expansion

### YAML structure

New: `cli/internal/scanner/quantum/quantum-readiness.yml`, embedded into Go binary via `//go:embed`, parsed with `gopkg.in/yaml.v3` (per CLAUDE.md Go conventions).

```yaml
version: 1
algorithms:
  - family: rsa
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM or ML-DSA"
    aliases: [rsa-pss, rsa-oaep, rsaes-pkcs1, rsassa-pkcs1, rsassa-pss]
  - family: ml-kem
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST PQC standard — recommended"
    aliases: [kyber, kyber-512, kyber-768, kyber-1024]
non_algorithm_asset_types:
  - related-crypto-material
  - certificate
```

### Lookup logic (replaces `quantum.go:65-75`)

```go
func GetInfo(input AlgorithmRef) Info {
    if input.AssetType != "" && nonAlgorithmTypes[input.AssetType] {
        return Info{Status: types.QuantumNotApplicable}
    }
    family := normalizeFamily(input.Name)  // "RSA-2048" → "rsa"; "aes-128-gcm" → "aes"
    if info, ok := table[family]; ok {
        return info
    }
    return Info{Status: types.QuantumUnknown, Recommendation: "Algorithm not recognized — review manually"}
}
```

### Name normalization

`normalizeFamily` — exact-match family root: strip `-<digits>(-<mode>)?` suffix via small regex, lowercase, lookup. If no exact-family match, return raw lowercased input (preserves "unknown" semantics, no false matches).

### New type

`types.QuantumNotApplicable` (added to `cli/internal/types/quantum.go`) — emitted for certificates/keys/secrets so PDF and CycloneDX output know to omit the quantum status field rather than render "Unknown".

### Initial table size

~80 families. Current 30 + ~50 additions:
- Full PQC suite: ML-KEM, ML-DSA, SLH-DSA, Falcon, XMSS, LMS, BIKE, HQC, FrodoKEM (with deprecated-alias mapping)
- Classical gaps: ElGamal, ECIES, KMAC, all SHA-2/SHA-3 variants, Poly1305, all HMAC variants, RIPEMD, Whirlpool, IDEA, SEED, ARIA, CAST5/6, RC2/5/6, Skipjack
- Password hashing: bcrypt, scrypt, Argon2i/d/id
- KDFs: HKDF, scrypt, Argon2id (PBKDF2 already present)

### Files touched (commit 2)

- **New:** `cli/internal/scanner/quantum/quantum-readiness.yml`
- **Modified:** `cli/internal/scanner/quantum/quantum.go` — replace inline map with YAML loader, add `normalizeFamily`, add `GetInfo` overload that takes AssetType
- **New:** `cli/internal/scanner/quantum/quantum_test.go` (expanded) — table-driven tests that every alias resolves to canonical, non-algorithm asset types skip lookup, fuzzy names (`RSA-2048`, `aes-128-gcm`) match family root
- **Modified:** `cli/internal/types/quantum.go` — add `QuantumNotApplicable`
- **Modified:** `cli/internal/output/{text,pdf,converter}.go` — handle `QuantumNotApplicable` (omit field rather than render "Unknown")

## Work item 3 — PDF Option D

### File split

Split `cli/internal/output/pdf.go` (732 lines) into `cli/internal/output/pdf/`:

```
renderer.go    — entry, generatePDF orchestrator
cover.go       — addCoverSection
summary.go     — addSummarySection (new aggregators + Option D breakdowns)
findings.go    — addFindingsTable (existing behavior preserved)
quantum.go     — addQuantumReadinessSection + addQuantumMigrationBacklog (new)
charts.go      — SVG generation via go-echarts → maroto image embed
compliance.go  — addComplianceSection (new, reads result.ComplianceResults if present)
diff.go        — addBaselineDiffSection (new, only if --baseline given)
shared.go      — colors, helpers (severityOrder, etc.)
```

### Summary aggregators

```go
type SummaryStats struct {
    Severity      map[types.Severity]int
    Quantum       map[types.QuantumStatus]int
    AssetType     map[string]int   // algorithm, certificate, protocol, related-crypto-material
    Primitive     map[string]int   // block-cipher, hash, signature, kdf, ...
    Language      map[string]int   // go, java, python, javascript, ...
    TopAlgorithms []KV             // sorted desc, top 10
    Files         int
    Languages     int
}

func aggregate(result *types.ScanResult) SummaryStats
```

### Chart approach

New dep: `github.com/go-echarts/go-echarts/v2`. Render charts to SVG bytes in `charts.go`, embed via maroto's image column.

Charts in this PR:
- Severity bar (5 bars: CRIT/HIGH/MED/LOW/INFO)
- Quantum mix pie (4 slices: Vulnerable/Safe/Unknown/Broken)
- Both ~120pt wide, side-by-side row

### Compliance section

Reads `result.ComplianceResults` (already populated per ADR-023 framework runs). Renders one tile per framework — NIST, FIPS, PCI-DSS, CNSA 2.0, ISO 27001, EU CRA — with pass/fail count + worst severity. Section is skipped entirely if no framework was run.

### Baseline diff (`--baseline <prev-scan.json>`)

Reuses `cli/internal/diff/` (existing per `/changelog` and `cradar diff` per CLAUDE.md).

PDF section: "Changes vs Baseline" with:
- Added (N), Resolved (N), Unchanged (N) summary tiles
- Top-10 newly added findings table (severity, file, name)

If flag omitted, section omitted.

### New CLI flag

`--baseline <path>` on `cradar scan` (in `cli/internal/cmd/scan.go`).

### Files touched (commit 3)

- **New:** `cli/internal/output/pdf/{renderer,cover,summary,findings,quantum,charts,compliance,diff,shared}.go` + `_test.go` for each
- **New:** `cli/internal/output/pdf/testdata/` — golden fixtures
- **Deleted:** `cli/internal/output/pdf.go` and `cli/internal/output/pdf_test.go` (replaced by package)
- **Modified:** `cli/internal/output/writer.go` — point at new package
- **Modified:** `cli/internal/cmd/scan.go` — add `--baseline` flag
- **Modified:** `cli/go.mod` / `go.sum` — add go-echarts dep

## Testing strategy

### Per-commit unit tests

| Commit | New tests |
|---|---|
| 1 | `normalize/*_test.go` (table-driven per enum + golden file inputs); `converter_test.go` updates for asset rerouting |
| 2 | `quantum_test.go` (every alias resolves to canonical; non-algorithm asset types skip; fuzzy names match family root); YAML round-trip |
| 3 | `pdf/*_test.go` split per file; `aggregate()` unit tests; golden PDF byte-comparison OR page-count + size sanity |

### Per-commit regression gates

Before each commit lands:
- `cd cli && go vet ./...` clean
- `cd cli && golangci-lint run` clean (per `/lint` skill)
- `cd cli && go test ./... -count=1` — all existing tests still pass
- Manual smoke: `./cradar scan ../scanner/rules/python/ --format pdf --output /tmp/x.pdf` succeeds without panic
- For commits 1 and 3: also `--validate` against generated CycloneDX JSON to confirm 0 errors

### Pre-PR final regression

- Full `go test ./...` count=1
- `cradar scan` on each of the 7 benchmark corpus languages (per `/benchmark` skill)
- Diff CBOM JSON output against pre-change baseline — confirm only-intended changes
- `cradar diff` still works (we didn't break it while reusing it from PDF)
- Generate PDF for sample-projects, eyeball via `view.sh`

### TDD application

Per `superpowers:test-driven-development`, every new function in `normalize/`, `pdf/`, and the expanded quantum table gets a failing test before implementation. Golden files for normalize and PDF kept small and committed to `testdata/`.

## Commit ordering and dependencies

Validation (commit 1) lands first because it corrects the data the other two consume. Quantum (commit 2) lands second because it expands the data model the PDF will summarize. PDF (commit 3) lands last because it depends on both. Each commit is independently green; if commit 3 grows beyond ~1500 LOC the PDF section may be split, but the target is one PR.

## Open questions

None remaining — all clarifying questions resolved during brainstorm. Implementation may surface follow-ups, captured as separate issues.

## Breaking changes (for CHANGELOG)

- CycloneDX output: `assetType` no longer emits `"library"`; values rerouted to `algorithm`, `certificate`, `protocol`, or `related-crypto-material` per the actual finding.
- CycloneDX output: `algorithmProperties.primitive` no longer emits `"HARDCODE-SECRET"` or other invented values; hardcoded secrets are now emitted as `assetType: related-crypto-material` with `relatedCryptoMaterialProperties.type: secret-parameter`.
- CycloneDX output: deprecated PQC algorithm names (Kyber, Dilithium, SPHINCS+, Falcon) are silently mapped to their NIST canonical names (ML-KEM, ML-DSA, SLH-DSA, FN-DSA).
- New CLI flags: `--strict-validate` (default off), `--baseline <path>` (default off).
