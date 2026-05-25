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
- The original `feature/cli-improvements` work items: rule-lifecycle metadata, **full** structured logging (slog adoption + JSONL log file at `~/.cradar/logs/`), multi-output format, shell completion, `cradar init`
- Any portal/backend/frontend changes
- Backwards-compat shims for invalid `assetType: "library"` or `primitive: "HARDCODE-SECRET"` (these were never valid CycloneDX, breaking change in CHANGELOG)

Note: commit 4 adds *minimal* scan-time progress feedback only, not the full slog/JSONL story. That remains in `feature/cli-improvements`. The two efforts will need to reconcile once both land.

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

## Work item 1 — Validation fix (revised after code audit)

### What's already done

Audit on 2026-05-25 revealed `converter.go` already has comprehensive normalization maps (`algorithmFamilyMap`, `primitiveMap`, `modeMap`, `paddingMap`, `cryptoFunctionMap`, `relatedCryptoMaterialTypeMap`) at lines 15-297. The 37 violations from `TODO-SCHEMA-VALIDATION.md` (concatkdf, fernet, aes-cmac, poly1305, x963kdf, etc.) are **all already mapped** at lines 108-119. So that historical sweep is done — TODO file is stale.

### What's actually broken

Two real bugs identified from current scanner output:

**Bug 1 — `AlgorithmPrimitive` bypass** (`converter.go:487-491`):
```go
primitive := normalizePrimitive(p.Primitive)
if p.AlgorithmPrimitive != "" {
    primitive = cyclonedx17.Primitive(p.AlgorithmPrimitive)  // ← raw cast, skips normalization
}
```
The scanner sets `p.AlgorithmPrimitive` to canonical algorithm tokens (`MD5`, `AES-256-GCM`) for OpenGrep findings, but also for hardcoded-secret findings at `cli/internal/scanner/config/config_scanner.go:122,189` it's set to `"HARDCODED-SECRET"`. The bypass emits that literal string into `algorithmProperties.primitive` where it fails CycloneDX 1.7 enum validation (closed set: `drbg | mac | block-cipher | stream-cipher | signature | hash | pke | xof | kdf | key-agree | kem | ae | combiner | key-wrap | other | unknown`).

**Bug 2 — `library` assetType bleed-through** (`converter.go:448`):
```go
cp := &cyclonedx17.CryptoProperties{
    AssetType: string(f.AssetType),  // ← passes "library" straight through
}
```
Two scanner-side sources, both pre-existing this branch:
- **OpenGrep YAML inventory rules** (since pre-rc.4) — every language's `cbom-<lang>-crypto-library-import` rule in `cli/internal/rules/data/*.yml` carries `cbom-asset-type: library` metadata. The parser at `cli/internal/opengrep/parser.go:114,184` falls through to `types.AssetType(s)` as-is for unknown values, so "library" reaches the converter verbatim. Confirmed in `v0.2.0-rc.4` (2026-05-20) — this is where the user's reported error originated.
- **YARA-X starter ruleset** (since `3ec4365`, 2026-05-25) — `cli/internal/yararules/data/openssl-versions.yar` and `crypto-library-signatures.yar` set `cbom_asset_type = "library"` for binary library-presence detection.

`library` is not in CycloneDX 1.7's `cryptoProperties.assetType` enum (`algorithm | certificate | protocol | related-crypto-material`). Library presence isn't a crypto asset semantically — it's an SBOM library entry and belongs in a regular CycloneDX `Component{Type: "library"}` instead.

Bug 1 has the same multi-source pattern: in addition to `config_scanner.go:122,189` setting `HARDCODED-SECRET`, the OpenGrep rules set `cbom-primitive: CRYPTO-LIBRARY-IMPORT` (also not in the `Primitive` enum). The converter fix catches both regardless of which scanner sourced them.

### Fixes

**Approach:** in-place fixes in `converter.go`. Skip the optional `normalize/` subpackage refactor (deferred — existing maps already serve their purpose well enough).

**Fix 1 — `AlgorithmPrimitive` bypass:** when `p.AlgorithmPrimitive` is set, run through `normalizePrimitive()` first. If the token is "HARDCODED-SECRET", reroute the finding to `assetType: related-crypto-material` with `relatedCryptoMaterialProperties.type: secret-parameter` (per CycloneDX 1.7 enum). If the token is a canonical algorithm name like `MD5`/`AES-256-GCM`, derive the proper primitive (`hash`/`block-cipher`) by family lookup. Otherwise, fall through to `PrimitiveOther` and tally a violation.

**Fix 2 — `library` assetType:** in `convertFinding`, special-case `f.AssetType == "library"` → emit a CycloneDX component with `Type: "library"` and **no** `CryptoProperties` block. Component name carries the library identifier from the YARA rule (e.g. `openssl`, `boringssl`). This is per-CycloneDX-1.7-spec: library presence belongs in regular SBOM components, not `cryptographicAsset`.

### Closed-set validation tally

Add a per-conversion validation tally that counts every value the normalizer had to fall back to a "preserves raw value" or "PrimitiveOther" path:

```go
type validationTally struct {
    Primitives          int
    AlgorithmFamilies   int
    Modes               int
    Paddings            int
    CryptoFunctions     int
    AssetTypes          int
    RelatedMaterialTypes int
    Total               int
    // First N example violations, for log enrichment.
    Examples []string
}
```

Each `normalize*` function increments the tally when it falls through to the "no map hit" branch. After `ConvertScanResult` finishes, the tally is logged to stderr at default verbosity (one summary line) and per-violation with `--verbose`. With `--strict-validate`, a non-zero tally returns an error from the converter (caller exits non-zero).

### Strict-validate flag

```go
// cli/internal/cmd/scan.go
scanCmd.Flags().Bool("strict-validate", false,
    "fail the scan if any output value falls outside the CycloneDX 1.7 enum closed sets (default: warn only)")
```

### Files touched (commit 1)

- **Modified:** `cli/internal/output/converter.go` — wrap normalize functions to take a `*validationTally`; fix `AlgorithmPrimitive` bypass at line 487-491; special-case `f.AssetType == "library"` in `convertFinding`; emit final tally.
- **Modified:** `cli/internal/output/converter_test.go` — golden-file tests for the two bug fixes + tally arithmetic.
- **New:** `cli/internal/output/converter_validation_test.go` — table-driven tests for each closed-set enum (asserts every CycloneDX 1.7 enum value round-trips, every known bad value normalizes correctly).
- **Modified:** `cli/internal/cmd/scan.go` — add `--strict-validate` flag; thread to converter; non-zero exit on strict failure.
- **Modified:** `cli/internal/scanner/config/config_scanner.go` — change `AlgorithmPrimitive: "HARDCODED-SECRET"` to set `AssetType: types.AssetRelatedCryptoMaterial` + `MaterialType: "secret-parameter"` directly at the scanner. (Optional: the converter rerouting also fixes this, but fixing at the source is cleaner. Both layers can coexist as defense-in-depth.)
- **Modified:** `cli/internal/scanner/config/config_scanner_test.go` — update assertions for the new emission shape.
- **Updated:** `docs/benchmark/TODO-SCHEMA-VALIDATION.md` — mark as historical/resolved, add note pointing to this commit and to `2026-05-25-cbom-export-quality-design.md`. Do NOT delete (preserves audit trail).
- **New:** `docs/decisions/ADR-034-library-asset-type.md` — record the design decision: YARA library findings emit as `type: library` components, not `cryptographic-asset`.

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

## Work item 4 — Scan-time progress visibility

### Problem

Today `cradar scan ./bigrepo` is silent from invocation until the final summary. Users on slow scans cannot tell whether the process is hung. `--verbose` is wired to `clilog.LevelVerbose` at `cli/internal/cmd/root.go:34-46` but scanner code in `cli/internal/scanner/*` and `cli/internal/opengrep/*` never calls clilog, so the flag is functionally silent.

This is **shell- and OS-agnostic** (TTY detection is per file descriptor, not per shell) — applies equally to bash, fish, ksh on macOS/Linux.

### Tight scope (this commit)

Add minimal progress emission. Defer the full structured-logging story (slog adoption, JSONL to `~/.cradar/logs/`, log enrichment) to `feature/cli-improvements`.

Three progress points, all emitted to stderr (never stdout — keeps the JSON output path clean):

1. **Walker heartbeat** — `cli/internal/scanner/walker.go`: emit one line per N files (default N=100) at default verbosity:
   ```
   [scan] walked 100 files (Go: 42, Java: 31, Python: 27)
   [scan] walked 200 files (...)
   ```
2. **Pass boundary** — `cli/internal/cmd/scan.go`: emit at start and end of Pass 1 (tree-sitter) and Pass 2 (OpenGrep):
   ```
   [scan] pass 1: tree-sitter starting (412 files)
   [scan] pass 1: tree-sitter complete (1.2s, 87 findings)
   [scan] pass 2: opengrep starting
   [scan] pass 2: opengrep complete (3.4s, 38 findings)
   ```
3. **Verbose mode** (`--verbose`) — emit per-file: `[scan] pass1 python: <file>` and per-rule-match. Existing log level integration via clilog.

### Throttling rules

- Default: heartbeat suppressed if total file count < 50 (avoids noise on small scans).
- Default: emit one heartbeat per 100 files OR every 2 seconds, whichever comes first.
- TTY detection (`output.IsTerminal(os.Stderr)`): on non-TTY, use plain lines; on TTY, optionally use `\r` carriage return to overwrite (configurable; default off for grep-ability).
- `--quiet` suppresses all progress lines.

### Always-on terminal summary (new)

In addition to per-step progress, **always emit a short scan summary to stderr at the end of every scan** so the terminal is never blank, regardless of where machine output goes. With `--output` set, additionally list each resolved output path.

Format (stderr, always):
```
[scan] complete in 4.2s — 142 findings (3 CRIT / 12 HIGH / 41 MED / 79 LOW / 7 INFO)
[scan] wrote /home/user/proj/scan.cbom.json (cyclonedx-json, 184 KB)
[scan] wrote /home/user/proj/report.pdf (pdf, 312 KB)
```

Duplication-avoidance rule (so the common TTY case isn't noisy):

| Scenario | stdout gets | stderr summary? |
|---|---|---|
| `cradar scan ./app` on a TTY (default → text format) | full text report on stdout | **suppressed** — already on stdout |
| `cradar scan ./app \| jq` (pipe, default → cyclonedx-json) | JSON | **emitted** — user has no terminal output otherwise |
| `cradar scan ./app -o x.json` (TTY, file output) | nothing | **emitted** + path lines |
| `cradar scan ./app -o x.pdf -o y.json` | nothing | **emitted** + both path lines |
| `cradar scan ./app --quiet` | format-dependent | **suppressed** (entire commit 4 is gated by `--quiet`) |

Implementation: in `writeOutputs`, after writing all destinations, compute the resolved-paths list. Pass it + the result to a new `emitFinalSummary(stderr, result, paths, stdoutFormat)` helper. The helper applies the rule table above.

Path format: always absolute (`filepath.Abs`) so users can click-to-open in modern terminals. Size shown via `os.Stat` post-write.

### Failure-mode coverage

User's specific reports:
- *"`cradar scan` with `--output cbom.json` shows nothing during scan"* → fixed by per-step progress events to stderr + the new always-on final summary listing the output path.
- *"silent execution makes you wonder if scan is happening"* → fixed by walker heartbeat (one line per 100 files or per 2s).

The "stdout silent when -o is set" behavior remains unchanged — it's correct (avoid duplicating output that's already in the file). The fix is that **stderr is no longer silent** — it carries progress + final summary + path list.

### Files touched (commit 4)

- **Modified:** `cli/internal/scanner/walker.go` — add heartbeat callback + file-count tracker
- **Modified:** `cli/internal/scanner/scanner.go` — wire progress callback through scanner runs
- **Modified:** `cli/internal/opengrep/runner.go` — emit pass 2 start/end events
- **Modified:** `cli/internal/cmd/scan.go` — wire callbacks, emit pass boundary lines
- **Modified:** `cli/internal/cmd/root.go` — add `--quiet` flag if not already present
- **New:** `cli/internal/cmd/progress.go` — small helper that formats and rate-limits progress lines
- **New:** `cli/internal/cmd/summary.go` — `emitFinalSummary` helper, duplication-avoidance rule, path+size listing
- **Modified:** `cli/internal/cmd/scan_test.go` — golden-output assertion for progress lines (use `--quiet` in existing tests that diff stderr)
- **New:** `cli/internal/cmd/progress_test.go` — rate-limiter unit tests
- **Modified:** CLI help text — document stdout vs. stderr behavior and `--output` silencing

## Testing strategy

### Per-commit unit tests

| Commit | New tests |
|---|---|
| 1 | `normalize/*_test.go` (table-driven per enum + golden file inputs); `converter_test.go` updates for asset rerouting |
| 2 | `quantum_test.go` (every alias resolves to canonical; non-algorithm asset types skip; fuzzy names match family root); YAML round-trip |
| 3 | `pdf/*_test.go` split per file; `aggregate()` unit tests; golden PDF byte-comparison OR page-count + size sanity |
| 4 | `progress_test.go` (rate-limiter + heartbeat formatting); `summary_test.go` (truth table for every duplication-avoidance scenario above); `scan_test.go` golden stderr lines with `--verbose` and default; ensure `--quiet` suppresses all progress + final summary |

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

Validation (commit 1) lands first because it corrects the data the other two consume. Quantum (commit 2) lands second because it expands the data model the PDF will summarize. PDF (commit 3) lands last because it depends on both. Scan-time progress (commit 4) is independent of 1–3 and lands last for review focus, but could be reordered without conflict. Each commit is independently green; if commit 3 grows beyond ~1500 LOC the PDF section may be split, but the target is one PR.

## Open questions

None remaining — all clarifying questions resolved during brainstorm. Implementation may surface follow-ups, captured as separate issues.

## Breaking changes (for CHANGELOG)

- CycloneDX output: `assetType` no longer emits `"library"`; values rerouted to `algorithm`, `certificate`, `protocol`, or `related-crypto-material` per the actual finding.
- CycloneDX output: `algorithmProperties.primitive` no longer emits `"HARDCODE-SECRET"` or other invented values; hardcoded secrets are now emitted as `assetType: related-crypto-material` with `relatedCryptoMaterialProperties.type: secret-parameter`.
- CycloneDX output: deprecated PQC algorithm names (Kyber, Dilithium, SPHINCS+, Falcon) are silently mapped to their NIST canonical names (ML-KEM, ML-DSA, SLH-DSA, FN-DSA).
- New CLI flags: `--strict-validate` (default off), `--baseline <path>` (default off).
