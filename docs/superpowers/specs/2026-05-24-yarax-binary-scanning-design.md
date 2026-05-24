# YARA-X Binary Scanning — Design

**Date:** 2026-05-24
**Status:** Draft (paired with ADR-039)
**Target release:** `0.3.0-rc.1` (or `0.2.x` minor, depending on cumulative scope)
**Baseline:** `fd8ce9e` (post-rc5)

This spec implements the decisions in **ADR-039** — read that first for the motivation and alternatives. This doc covers the concrete plumbing.

---

## 1. Scope

Four sub-PRs (A → D), bisectable, each shippable on its own. End state:

- New `cli/internal/scanner/yarax/` package — subprocess wrapper around `yr`, implements `scanner.Scanner`.
- Embedded ruleset at `scanner/yara-rules/*.yar` → `cli/internal/yararules/data/*.yar` (synced via `go generate`).
- Pass-3 attribution wired into `runScan` and `--passes`.
- YARA-X download path gains SHA-256 verification (closes ADR-038 gap).
- CLI usage guide (`docs/guides/cli/commands.md`) updated.

## 2. File layout

```
cli/internal/scanner/yarax/
├── runner.go              # Runner type, NewRunner lookup, Scan method
├── runner_test.go         # subprocess + parse coverage
├── parser.go              # YARA-X JSON output → []types.Finding
├── parser_test.go
├── canonicalize.go        # rule-meta → cbom-primitive (mirrors opengrep parser)
├── canonicalize_test.go
└── testdata/
    ├── rules/
    │   ├── good/example.yar
    │   └── broken/bad-syntax.yar
    └── output/
        └── sample-yr-output.json

scanner/yara-rules/                   # source-of-truth ruleset
├── openssl-versions.yar
├── libsodium-signatures.yar
├── boringssl-mbedtls-magic.yar
├── embedded-pem-blobs.yar
├── rsa-private-key-markers.yar
├── aes-sbox-constants.yar
├── aes-round-constants.yar
├── jwt-signing-keys.yar
└── README.md                         # ruleset overview + how to add a rule

cli/internal/yararules/
├── data/                             # embedded copy synced via go generate
└── embed.go                          # //go:embed data/*.yar
```

## 3. Sub-PR A — runner + scanner skeleton

**Files added/modified:**

| File | Change |
|---|---|
| `cli/internal/scanner/yarax/runner.go` | New — `NewRunner()` discovery, `Available()`, `Scan(target, rulesDir)` |
| `cli/internal/scanner/yarax/parser.go` | New — minimal struct: parse `yr --json` results, return empty `[]Finding` (no canonicalization yet) |
| `cli/internal/scanner/yarax/runner_test.go` | New — `TestNewRunner_LookupOrder`, `TestScan_SoftSkipWhenAbsent` |
| `cli/internal/scannerinit/defaults.go` | Register YARA-X scanner for `.so .dll .dylib .exe .class .jar .whl .a .o .wasm` |
| `cli/internal/cmd/scan.go` | New `pass3Required` tracking (mirrors `pass2Required`), `runPass3` analog |
| `cli/pkg/log/log.go` | New helper: `Logger.YaraXScanFire(target string)` — debug-level event when YARA-X invoked |

**`NewRunner` lookup order** (matches `cli/internal/opengrep/runner.go:28-65`):
1. Next-to-cradar binary (`os.Executable()` dir + `/yr`)
2. `$CRADAR_TOOLS_DIR/yr`
3. `~/.cradar/tools/yr`
4. `$PATH` via `exec.LookPath("yr")`
5. Return `nil` if none found

**Soft-skip path:** when `runner == nil || !runner.Available()`, log a one-line note to stderr (`Pass 3 skipped — yr not found. Run 'cradar install-tools' or use cradar-full.`) and return `nil, nil`. Same UX as the OpenGrep soft-skip in `runPass2`.

**Hard-fail path:** when `--passes 3` is explicitly requested (via `--deep` extension OR `--passes` flag containing `3`) AND `yr` is absent, return `ExitErrorf(ExitToolMissing, "Pass 3 requires yr...")`. Same pattern as Bug 4's exit-4 contract.

**`Scan` invocation:**

```bash
yr scan --output-format json --rules-path <rulesDir> <target-file>
```

Per-file (not per-directory) because we want isolation per-file for accurate path attribution. Batching multiple files per invocation is a Sub-PR C optimization if startup overhead is measurable. Initial implementation: one subprocess per file.

**Soft errors from `yr`:** if a single rule file fails to compile, `yr` returns warnings but continues. Capture stderr, log warnings, don't fail the run. (Parallel to ADR-036's opengrep skip-and-warn.)

**Tests for sub-PR A:**

```go
func TestNewRunner_LookupOrder(t *testing.T) { ... }
func TestRunner_AvailableReportsTrueWhenBinary(t *testing.T) { ... }
func TestRunner_ScanSoftSkipsWhenAbsent(t *testing.T) { ... }
func TestRunner_ScanFiresOnRegisteredExtensions(t *testing.T) {
  // Run cradar scan on a tempdir with one .so file. Verify YARA-X
  // was invoked via the debug log event.
}
```

## 4. Sub-PR B — embedded starter ruleset

**Ruleset structure** (each `.yar` file):

```yara
rule openssl_version_3_0 {
  meta:
    author        = "cradar"
    description   = "OpenSSL 3.0.x version string in binary"
    cbom_primitive   = "OPENSSL-3.0"
    cbom_asset_type  = "library"
    cbom_library     = "openssl"
    category         = "inventory"
    maturity         = "stable"
    default_enabled  = "true"
    noise_risk       = "low"
  strings:
    $ver = /OpenSSL 3\.0\.[0-9]+(\s|\x00)/
  condition:
    $ver
}
```

The `meta` block carries the **same canonical-token vocabulary** PR #4 established for OpenGrep rules. The YARA-X parser reads `cbom_primitive` / `cbom_asset_type` / etc. and emits findings with matching `algorithmProperties`.

**Initial 15 rules** (rough grouping, each in its own file or grouped logically):

| Rule | Detects |
|---|---|
| `openssl_version_*` | OpenSSL 1.0.x / 1.1.x / 3.0.x / 3.1.x version strings |
| `libsodium_signature` | `sodium_init` import / version string |
| `boringssl_magic` | BoringSSL build-tag strings |
| `mbedtls_signature` | mbedTLS version constants |
| `embedded_pem_certificate` | `-----BEGIN CERTIFICATE-----` block found in binary |
| `embedded_pem_rsa_private` | `-----BEGIN RSA PRIVATE KEY-----` in binary |
| `embedded_pem_ec_private` | `-----BEGIN EC PRIVATE KEY-----` in binary |
| `embedded_pkcs8_private` | `-----BEGIN PRIVATE KEY-----` (PKCS#8) in binary |
| `aes_sbox_forward` | AES forward S-box byte sequence |
| `aes_sbox_inverse` | AES inverse S-box byte sequence |
| `aes_rcon` | AES round constants |
| `des_sbox` | DES S-box patterns |
| `md5_constants` | MD5 magic constants |
| `sha1_constants` | SHA-1 magic constants |
| `sha256_constants` | SHA-256 round constants |

**Parser changes (sub-PR B):**

`cli/internal/scanner/yarax/canonicalize.go`:

```go
type yaraMeta struct {
    CbomPrimitive   string
    CbomAssetType   string
    CbomLibrary     string
    Category        string
    Maturity        string
    DefaultEnabled  bool
    NoiseRisk       string
}

func parseMeta(rawMeta []yaraMetaEntry) yaraMeta { ... }
```

Findings populate `Properties.AlgorithmPrimitive`, `Properties.Library`, `Category`, `Maturity` exactly like OpenGrep parser does. Reuses `canonicalizePrimitive` from `cli/internal/opengrep/parser.go` — same vocabulary, no duplication.

**Tests for sub-PR B:**

```go
func TestParser_RuleMetaToFinding(t *testing.T) { ... }     // uses testdata/output/sample-yr-output.json
func TestRuleset_AllRulesHaveCbomPrimitive(t *testing.T) {  // guard like TestNoCoarseMarkers
  // Scan scanner/yara-rules/*.yar, assert every rule's meta has cbom_primitive
}
```

## 5. Sub-PR C — pass-3 wiring + YARA-X SHA-256 verification

**`cli/internal/cmd/scan.go`:**

```go
passesStr := cmd.Flags().GetString("passes")
// parsePasses now accepts 1, 2, 3, or any comma-separated subset.
// --deep is sugar for --passes 1,2,3 (was 1,2 in rc5).
```

`parsePasses` already exists at `cli/internal/cmd/scan.go` — extend its allowed-set from `{1,2}` to `{1,2,3}`. Adjust the existing test (the same test that was the rc1 pre-existing baseline failure).

**YARA-X SHA-256 verification (closes ADR-038 gap):**

`cli/internal/tools/installer.go` — `InstallYARAX` currently downloads without checksum. Apply the same `fetchReleaseAsset` + `VerifySHA256` pattern as OpenGrep:

```go
binURL, expectedSum, err := fetchReleaseAsset(
    "https://api.github.com/repos/VirusTotal/yara-x/releases/tags/v1.14.0",
    "yara-x-v1.14.0-x86_64-unknown-linux-gnu.gz",
)
tmpPath, err := downloadToTemp(binURL, ...)
err = VerifySHA256(tmpPath, expectedSum)
```

VirusTotal's release API also returns a `digest` field per asset, so the existing helper works without modification.

**Tests for sub-PR C:**

```go
func TestParsePasses_AcceptsPass3(t *testing.T) { ... }
func TestRunPass3_MissingAndNotRequired_SoftSkip(t *testing.T) { ... }
func TestRunPass3_MissingAndRequired_ExitToolMissing(t *testing.T) { ... }
func TestInstallYARAX_VerifiesSHA256(t *testing.T) { ... }  // httptest mock release API
func TestInstallYARAX_ChecksumMismatchFails(t *testing.T) { ... }
```

## 6. Sub-PR D — docs + smoke + version

**`docs/guides/cli/commands.md`:** new entry for `--passes` accepting `3`, brief note on what Pass 3 covers. New section under the `scan` subcommand explaining when YARA-X runs.

**`docs/guides/cli/workflows.md`:** new workflow recipe — "Scanning compiled binaries for embedded crypto" — example invocations + sample output.

**`docs/recall-improvement-plan.md`:** mark Phase D as superseded by Phase 5+ deep-scan work.

**`CHANGELOG.md`:** new entry under `0.3.0-rc.1` (or wherever sub-PR D lands):

```markdown
## 0.3.0-rc.1 — YYYY-MM-DD

### New: Pass 3 binary crypto detection (YARA-X)

cradar now invokes YARA-X (the `yr` binary already bundled in cradar-full)
to detect cryptographic assets inside compiled binaries — .so / .dll /
.dylib / .exe / .class / .jar / .whl / .wasm and OCI container layer
contents. Initial ruleset (15 rules) covers OpenSSL / libsodium /
BoringSSL / mbedTLS version detection, embedded PEM blobs, common AES /
DES / MD5 / SHA constants. Closes the long-standing "yr is shipped but
never used" gap (see ADR-039).

- New `--passes 3` flag; `--deep` now expands to `1,2,3`.
- Soft-skip when `yr` is absent (matches OpenGrep behavior).
- YARA-X install path now SHA-256-verified via GitHub API digest
  (parallel to ADR-038 for OpenGrep).
```

**Container-scan smoke test (manual or scripted):**

```bash
cradar scan --container alpine:3.18 --passes 1,2,3 --format text
# Expect: Pass 3 findings — openssl_version_3_0, libsodium_signature, etc.
```

**VERSION:** bump to `0.3.0-rc.1`.

## 7. Test-bench update

`/home/nk-sentinel/projects/CipherRadarTestProj` does not currently have any compiled binaries that would exercise YARA-X meaningfully. Two options:

**A. Don't add fixtures.** Verify with `alpine:3.18` (or another small image) for container-scan testing; verify rule-firing with single-file unit tests in `cli/internal/scanner/yarax/testdata/`.

**B. Add a `binaries/` subdir to CipherRadarTestProj** with a few representative built artifacts — a tiny C program statically linked against OpenSSL, a hello-world Java JAR with BouncyCastle on the classpath, etc.

**Recommended:** A for sub-PRs A-C. B optional in sub-PR D if recall measurement on a known fixture corpus is wanted.

## 8. Risks / open questions

1. **YARA-X JSON output format.** `yr scan --output-format json` produces a slightly different shape than Semgrep / OpenGrep. Sub-PR A's `parser.go` needs to handle the actual format; verify by running `yr scan --output-format json` against a tiny fixture early.
2. **Subprocess startup overhead.** Per-file `yr` invocation may be slow on large repos. Sub-PR C should measure. If significant (>5% of scan time), batch invocations in C as a follow-up.
3. **Rule conflict with native binary scanner.** Both run for the same extension set. Duplicates are possible (e.g., AES S-box detected by both). De-duplication via `Finding.Fingerprint` (already implemented per ADR-034) should handle this naturally — verify in sub-PR B.
4. **License compatibility.** YARA-X is BSD-3-Clause. Compatible with our Apache 2.0 for the CLI. The bundled `yr` binary's redistribution within `cradar-full` is fine under both.
5. **WASM scanning.** Sub-PR A registers `.wasm` but the initial rules don't have WASM-specific patterns. Phase 5 work would add those; this ADR/spec doesn't.

## 9. Total effort + sequencing

| Sub-PR | Effort | Depends on |
|---|---|---|
| A — runner skeleton | 3-4 days | nothing |
| B — starter ruleset + parser | 3-4 days | A |
| C — pass-3 wiring + SHA verify | 2-3 days | B |
| D — docs + smoke + version | 1-2 days | C |
| **Total** | **~2 weeks** | sequential |

Sub-PR D ships `0.3.0-rc.1` (or `0.2.x` minor).
