# rc1 Bug Fixes — Design

**Date:** 2026-05-18
**Branch:** `feature/cli-improvements`
**Target release:** `0.2.0-rc.2`
**Baseline:** `f254c1d` (clean — `go test -race ./...` passes across 41 packages)

---

## 1. Background

`docs/cli-improvements-bugs.md` catalogues 8 bugs found end-to-end against
`CipherRadarTestProj` on 2026-05-09 with `cradar` built from `a362d8f`
(VERSION `0.2.0-rc.1`). This spec scopes the fix campaign for rc2.

## 2. Scope decisions

| # | In/out | Rationale |
|---|---|---|
| 1 | **In** — exit 3 on missing scan path | High-severity CI trap; one-line policy contract violation |
| 2 | **In** — wrap `--category` typo as `ExitConfigError` | Documented contract drift |
| 3 | **In** — wire per-scanner / per-finding instrumentation | Item 2 deferred follow-up; flags exist but do nothing today |
| 4 | **In** — `--only-inventory` hint when pass-2 absent | Cheap UX win |
| 5 | **In** — installer URL fix + SHA-256 checksum verification | Blocks fresh-install; closes supply-chain gap |
| 6 | **In** — cradar-side hardening only (skip-and-warn + surface errors) | Restores Pass 2 for languages with clean rule files; user explicitly excluded rule rewrites |
| 7 | **Out** | User-decided. Documented limitation; cradar will surface which files were skipped |
| 8 | **In** — strip opengrep namespace prefix from `RuleID` | Restores `--rules` / `--disable-rule` for opengrep findings |

**Branch / PR strategy:** continue on `feature/cli-improvements`, one
commit per bug (bisectable history), single PR at the end. `0.2.0-rc.2`
+ CHANGELOG update as the final commit. No ADR required for bugs 1–4, 8;
a new ADR-038 covers the installer checksum verification (new security
posture).

## 3. Commit order

Trivial → invasive, so each commit lands on a green tree.

| # | Bug | Touches | Size |
|---|---|---|---|
| C1 | Bug 2 — wrap `--category` typo in `ExitErrorf(ExitConfigError, …)` | `scan.go`, test | XS |
| C2 | Bug 8 — strip opengrep namespace prefix from `RuleID` | `parser.go`, test | XS |
| C3 | Bug 4 — emit hint when `--only-inventory` + pass-2 was skipped | `scan.go`, test | XS |
| C4 | Bug 1 — validate scan target exists/readable before walking; return exit 3 | `scan.go`, test | S |
| C5 | Bug 5 — fix installer URL + SHA-256 checksum verification | `installer.go`, new `checksum.go`, tests | M |
| C6 | Bug 6 — opengrep pre-validate, skip-and-warn, surface `output.Errors` | `runner.go`, `parser.go`, tests | M |
| C7 | Bug 3 — wire per-scanner / per-finding log events + `source` field | `pkg/log`, scanners, `scan.go` | M-L |
| C8 | docs — bugs-doc status updates, ADR-038, CHANGELOG, VERSION bump | docs only | S |

## 4. Component design

### 4.1 Installer hardening (C5 — Bug 5)

- **`cli/internal/tools/installer.go`** — replace per-asset URL/arch
  table with a struct: `{Platform, AssetURL, ChecksumURL}`. For
  linux/amd64 the working asset is the standalone single-file binary
  `opengrep_manylinux_x86`; the `amd64 → x86_64` rewrite is dropped.
  YARA-X retains its existing asset mapping.
- **New `cli/internal/tools/checksum.go`** — `VerifySHA256(path string,
  expected string) error`. Pure-stdlib (`crypto/sha256`, `io`). Keeps
  `installer.go` from growing.
- **Flow per asset:**
  1. Fetch `<asset>.sha256` over HTTPS (reject non-`https://` schemes).
  2. Parse the expected hex digest.
  3. Stream binary download into a temp file in the destination dir.
  4. `VerifySHA256(tempPath, expected)`; on mismatch delete temp file
     and return `ExitErrorf(ExitToolError, "checksum mismatch …")`.
  5. `chmod 0755`, atomic rename to final path.
- **Trust anchor:** the GitHub release's published `*.sha256` file. The
  fix does not add code-signing verification — that's a separate ADR.

### 4.2 Opengrep skip-and-warn (C6 — Bug 6 + Bug 8)

Single commit; two-file change.

**`cli/internal/opengrep/runner.go`:**
- New `loadableRuleFiles(rulesDir string, log *log.Logger) []string`:
  - Walk `*.yml` in `rulesDir`.
  - For each file, run `opengrep validate <file>` (subprocess exit
    code only — no JSON parsing required).
  - Files that fail validation get a structured `log.Warn` entry
    (`{event: "opengrep_rule_skipped", rule_file, reason}`) and are
    excluded from the scan invocation.
  - If `len(loadable) == 0`, return `ExitErrorf(ExitToolError,
    "no loadable opengrep rule files in %s")`.
- Replace `--config <dir>` with N × `--config <file>` (opengrep
  accepts repeated `--config`). This also has the side-effect of
  removing the directory-name namespace prefix from `check_id`, but we
  don't rely on it (see parser change).

**`cli/internal/opengrep/parser.go`:**
- After `json.Unmarshal`, if `len(output.Errors) > 0`, emit a
  structured `log.Warn` per error (`{event: "opengrep_runtime_error",
  rule_file, severity, message}`).
- Behavior preserved: when `len(Results) > 0`, return findings even
  if errors exist (best-effort delivery).
- Namespace-prefix stripping (Bug 8) is **owned by C2**, not this
  commit. C6's switch to per-file `--config` invocation eliminates the
  prefix as a side effect, which means C2's strip logic becomes
  defensive after C6 lands. Test fixtures in C2 cover both pre- and
  post-C6 inputs so the strip stays correct under either invocation
  style.

**Trade-off accepted:** `opengrep validate` adds N ≈ 12 subprocess
invocations once per scan (~80-200ms wall on the test bench).
Section 6 sets a perf gate.

### 4.3 Debug instrumentation (C7 — Bug 3)

Minimal wiring; no observability overhaul.

**`cli/pkg/log`** — three helpers, all redaction-aware (existing
logger already handles secret patterns):
- `Logger.ScannerStart(scanner string, target string)`
- `Logger.ScannerComplete(scanner string, findingCount int, duration time.Duration)`
- `Logger.FindingEmitted(scanner string, ruleID string, severity string, path string, source string)`

`source` is the matched code snippet (truncated to 200 chars). When
`--log-include-source` is unset, callers pass `""` and the field is
omitted from the JSONL line.

**Call sites:**
- `scan.go` runner loop: `ScannerStart` / `ScannerComplete` per
  registered scanner per pass.
- Each AST scanner package's finding-emit path: one
  `FindingEmitted` call per finding. ~12 sites.
- `opengrep/parser.go`: one `FindingEmitted` call per parsed finding.

**Out of scope:** concurrent-scan log interleaving (separate deferred
item from rc1). Lines may interleave in `--log-format text`; JSONL
remains parseable.

### 4.4 Path validation (C4 — Bug 1)

In `scan.go`, immediately after flag parsing and before
`scanner.ScanDirWithOptions`:

```go
info, err := os.Stat(targetPath)
if err != nil {
    if os.IsNotExist(err) {
        return ExitErrorf(ExitConfigError, "scan path does not exist: %s", targetPath)
    }
    return ExitErrorf(ExitConfigError, "cannot stat scan path %s: %v", targetPath, err)
}
if !info.IsDir() {
    return ExitErrorf(ExitConfigError, "scan path is not a directory: %s", targetPath)
}
```

Symlinks resolve via `os.Stat` (follows) → if the target is OK, we
proceed. No path-traversal "denylist" — cradar is a developer tool,
not a sandbox. Test asserts behavior for missing path, file path,
unreadable path.

### 4.5 Hint for `--only-inventory` (C3 — Bug 4)

In `scan.go`, after the scan completes, before writing output:

```go
if cfg.OnlyInventory && !pass2Ran {
    fmt.Fprintln(cmd.ErrOrStderr(),
        "Note: --only-inventory matched 0 findings; inventory rules require Pass 2. " +
        "Run 'cradar install-tools' or pass --passes 1,2.")
}
```

`pass2Ran` is already tracked by the runner. No filter logic changes.

### 4.6 Exit-code wrap (C1 — Bug 2)

`cli/internal/cmd/scan.go:723` (the `parseRuleFilterOptions` return
site): change `fmt.Errorf(...)` to `ExitErrorf(ExitConfigError, ...)`.
One-line fix. The validator helper inside `rulefilter/` stays plain;
the cmd-layer call site is responsible for exit-code typing per ADR-036.

## 5. Test plan (functional / regression / perf / security)

### 5.1 Functional (unit, per bug)

Each commit lands with its tests. New test names:

| Bug | Test | Location |
|---|---|---|
| 2 | `TestScanCommand_BadCategoryExitsConfigError` | `cli/internal/cmd/scan_test.go` |
| 8 | `TestParseResults_StripsNamespacePrefix` | `cli/internal/opengrep/parser_test.go` |
| 4 | `TestOnlyInventory_HintWhenPass2Skipped` | `cli/internal/cmd/scan_test.go` |
| 1 | `TestScanCommand_MissingPathExitsConfigError`, `TestScanCommand_NonDirectoryPathExitsConfigError`, `TestScanCommand_UnreadablePathExitsConfigError` | `cli/internal/cmd/scan_test.go` |
| 5 | `TestInstaller_ChecksumMismatchRejected`, `TestInstaller_ValidChecksumAccepted`, `TestInstaller_LinuxAmd64UsesCorrectURL`, `TestInstaller_RejectsNonHTTPS` | `cli/internal/tools/installer_test.go` |
| 6 | `TestRunner_SkipsBrokenRuleFiles`, `TestParser_SurfacesErrorsArray`, `TestRunner_AllRulesBrokenReturnsToolError` | `cli/internal/opengrep/{runner,parser}_test.go` |
| 3 | `TestLogger_ScannerLifecycleEvents`, `TestLogger_SourceFieldPopulatedWhenFlagSet`, `TestLogger_SourceFieldOmittedByDefault`, `TestLogger_SourceFieldRedactsSecrets` | `cli/pkg/log/log_test.go` + `scan_test.go` |

**Fixtures:** hand-written rule files under `cli/internal/opengrep/testdata/rules/{good,broken}/` (independent of `scanner/rules/`). Installer tests use `net/http/httptest` for asset + checksum endpoints.

### 5.2 Regression

- **Baseline:** `f254c1d` is the clean baseline. `go test -race ./...`
  must stay green after every commit.
- **Per-commit gate:** `go test -race ./...` run before `git commit`;
  any new failure blocks the commit.
- **End-to-end smoke** against `/home/nk-sentinel/projects/CipherRadarTestProj`:
  - Pre-rc2 baseline (one-time): `cradar scan . --passes 1` finding
    count + `cradar scan . --passes 2` finding count, captured to
    `/tmp/rc2-smoke-pre.txt`.
  - After C6 (Bug 6 lands): re-run; assert Pass 1 count **unchanged**;
    record new Pass 2 count as the rc2 baseline (expected to grow
    since cradar will now skip broken rule files and still run the
    clean ones — Python/Go users remain at near-zero coverage by
    design per scope decision on Bug 7).
- **`/lint`** (`golangci-lint + go vet`) green on the final tree.
- **`/test-coverage`** thresholds hold per package.

### 5.3 Performance

Use `/benchmark` skill on the test bench. Median of 3 runs each.

| Metric | Pre baseline | Gate |
|---|---|---|
| Pass 1 wall time | measured pre-C7 | ≤ 3% regression (only C7 touches the pass-1 hot path) |
| Pass 2 wall time | measured pre-C6 | ≤ 10% absolute regression (C6 adds N `opengrep validate` subprocess calls) |
| Peak RSS (both passes) | measured pre-C5 | ≤ 5% regression |

**If C7 regresses Pass 1 > 3%:** profile via `/profile`, gate the
`FindingEmitted` call behind logger-level check before building the
structured event.

**If C6 regresses Pass 2 > 10%:** parallelize `opengrep validate`
calls (`errgroup` over rule files). Only optimize if measured.

**Recording:** numbers go in the PR description so reviewers see the
delta inline.

### 5.4 Security

`/sec-review` (`gosec + govulncheck`) on every commit. Targeted tests:

- **C5 (supply chain):**
  - `TestInstaller_ChecksumMismatchRejected` — mutate one byte of
    the served binary → install fails with `ExitToolError`.
  - `TestInstaller_RejectsNonHTTPS` — httptest server URL rewritten
    to `http://` → installer refuses.
  - `govulncheck` on the diff: no new module deps expected (`crypto/sha256`
    is stdlib).
- **C4 (path validation):**
  - `TestScanCommand_RejectsSpecialFile` — `os.Stat` against
    `/dev/null` → exit 3 with "not a directory".
- **C6 (untrusted rule files):**
  - `TestRunner_MalformedYAMLDoesNotPanic` — fixture: rule file with
    deeply-nested YAML anchors / 1 MB content → `opengrep validate`
    rejects it, cradar logs and continues.
  - `TestRunner_NoShellInjection` — rule file path `; rm -rf /.yml`
    is passed as argv via `exec.Command` (not via `sh -c`); assert
    argv equality, not stdout.
- **C7 (log redaction):**
  - Existing redaction tests stay green.
  - `TestLogger_SourceFieldRedactsSecrets` — `source` snippet
    containing `AKIA…` or `-----BEGIN PRIVATE KEY-----` is redacted
    in the JSONL output.

## 6. Documentation

- **`docs/cli-improvements-bugs.md`** — append status line per bug
  (FIXED in `<commit>`, DEFERRED for #7, ALREADY-LIMITATION for #4 hint).
- **New `docs/decisions/ADR-038.md`** — Installer checksum
  verification (decision, alternatives, trust anchor, future work).
- **`CHANGELOG.md`** — single rc2 section listing fixes by bug
  number, citing commit hashes.
- **`VERSION`** — bump to `0.2.0-rc.2`.

## 7. Test bench

- Reuse `/home/nk-sentinel/projects/CipherRadarTestProj`. Existing
  `.cradar.yml`, `policy.cradar.yml`, `.cradar-baseline.json` stay.
- Opengrep currently at `~/.cradar/tools/opengrep` from manual install.
  Once C5 lands, validate by `rm ~/.cradar/tools/opengrep` and running
  `cradar install-tools` fresh.

## 8. Out of scope (recorded so they're not forgotten)

- Bug 7 — rule file rewrites for Python/Go/Dart/Rust. User decided.
- Concurrent-scan log interleaving (separate deferred follow-up).
- Item 5 from the CLI improvements plan (schema enum fixes, LLM/OTel
  CLI surfaces, progress bar).
- Code-signing verification for installed binaries (beyond SHA-256).
- `cradar install-tools` for ARM / macOS — current scope is
  linux/amd64 parity with the existing installer.

## 9. Open questions

None at time of writing. All scope decisions captured above.
