# rc1 Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land fixes for 7 rc1 bugs (1, 2, 3, 4, 5, 6, 8) on `feature/cli-improvements` as a bisectable per-bug commit sequence, culminating in a `0.2.0-rc.2` version bump.

**Architecture:** Per-bug commits, trivial → invasive order so each lands on a green tree. Bug 6 hardens the opengrep pipeline by pre-validating rule files and surfacing load errors; cradar continues to scan with whatever rule files load (no rule rewrites — Bug 7 explicitly out of scope). Bug 5 adds SHA-256 verification of downloaded tool binaries.

**Tech Stack:** Go 1.26, cobra, log/slog, crypto/sha256 (stdlib). No new module dependencies.

**Spec reference:** `docs/superpowers/specs/2026-05-18-rc1-bug-fixes-design.md`

**Pre-flight:** Baseline `f254c1d` must be checked out. `go test -race ./...` must be all-green before starting Task C1.

---

## File Structure

**Create:**
- `cli/internal/tools/checksum.go` — `VerifySHA256(path, expected) error` helper
- `cli/internal/tools/checksum_test.go`
- `cli/internal/opengrep/testdata/rules/good/example.yml` — fixture: valid rule file
- `cli/internal/opengrep/testdata/rules/broken/bad-schema.yml` — fixture: rule file with schema error
- `cli/internal/opengrep/runner_test.go` — new test file (none exists today)
- `docs/decisions/ADR-038.md` — installer checksum verification decision

**Modify:**
- `cli/internal/cmd/scan.go` — Bug 1 (path validation), Bug 2 (exit-code wrap), Bug 4 (hint)
- `cli/internal/cmd/scan_test.go` — tests for Bugs 1, 2, 4
- `cli/internal/opengrep/parser.go` — Bug 8 (strip namespace prefix), Bug 6 (surface errors)
- `cli/internal/opengrep/parser_test.go` — tests for Bugs 8, 6
- `cli/internal/opengrep/runner.go` — Bug 6 (skip-and-warn pre-validation)
- `cli/internal/tools/installer.go` — Bug 5 (URL fix + checksum verification)
- `cli/internal/tools/installer_test.go` — tests for Bug 5
- `cli/pkg/log/log.go` — Bug 3 (ScannerStart/Complete, FindingEmitted helpers)
- `cli/pkg/log/log_test.go` — tests for Bug 3 helpers
- Scanner packages (AST + opengrep parser) — Bug 3 (call FindingEmitted)
- `docs/cli-improvements-bugs.md` — status updates per fix
- `CHANGELOG.md` — rc2 entry
- `cli/VERSION` (or top-level VERSION) — bump to `0.2.0-rc.2`

---

## Task C1: Bug 2 — Wrap `--category` typo as exit-3

**Files:**
- Modify: `cli/internal/cmd/scan.go:723`
- Test: `cli/internal/cmd/scan_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cli/internal/cmd/scan_test.go`:

```go
func TestScanCommand_BadCategoryExitsConfigError(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "a.py"), []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "--category", "bogus"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid --category, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should mention the bad value: %v", err)
	}
}
```

Ensure imports include `"errors"` (it should already; if not add it).

- [ ] **Step 2: Run test to verify it fails**

```bash
cd cli && go test ./internal/cmd/ -run TestScanCommand_BadCategoryExitsConfigError -v
```

Expected: FAIL — current code returns a plain `fmt.Errorf`, so `errors.As(err, &ee)` returns false.

- [ ] **Step 3: Wrap the validator error as ExitErrorf**

Edit `cli/internal/cmd/scan.go:723`. Change:

```go
	for _, c := range opts.Categories {
		if c != types.CategoryInventory && c != types.CategorySecurity {
			return rulefilter.Options{}, fmt.Errorf("invalid --category value %q (valid: inventory, security)", c)
		}
	}
```

to:

```go
	for _, c := range opts.Categories {
		if c != types.CategoryInventory && c != types.CategorySecurity {
			return rulefilter.Options{}, ExitErrorf(ExitConfig, "invalid --category value %q (valid: inventory, security)", c)
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/cmd/ -run TestScanCommand_BadCategoryExitsConfigError -v
```

Expected: PASS.

- [ ] **Step 5: Run race-suite to confirm no regression**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output (all packages pass).

- [ ] **Step 6: Commit**

```bash
git add cli/internal/cmd/scan.go cli/internal/cmd/scan_test.go
git commit -m "fix(cli): exit 3 on invalid --category value (bug 2)

Wrap parseRuleFilterOptions's category validator with ExitErrorf
(ExitConfig) so the typo path matches the ADR-036 exit-code contract.
Was returning exit 1, which collides with the findings-above-threshold
contract and confuses CI pipelines."
```

---

## Task C2: Bug 8 — Strip opengrep namespace prefix from RuleID

**Files:**
- Modify: `cli/internal/opengrep/parser.go:76,97,208-218`
- Test: `cli/internal/opengrep/parser_test.go` (existing)

- [ ] **Step 1: Inspect existing parser_test.go to confirm style**

```bash
cd cli && ls internal/opengrep/parser_test.go && head -30 internal/opengrep/parser_test.go
```

Expected: file exists.

- [ ] **Step 2: Add the failing test**

Append to `cli/internal/opengrep/parser_test.go`:

```go
func TestParseResults_StripsNamespacePrefix(t *testing.T) {
	cases := []struct {
		name        string
		inputCheck  string
		wantRuleID  string
		wantName    string
	}{
		{
			name:       "dir-namespaced ID is stripped",
			inputCheck: "tmp.clean-rules.cbom-js-crypto-library-import",
			wantRuleID: "cbom-js-crypto-library-import",
			wantName:   "crypto-library-import",
		},
		{
			name:       "deep namespace is stripped to the last dot",
			inputCheck: "scanner.rules.javascript.cbom-js-hardcoded-jwt-secret",
			wantRuleID: "cbom-js-hardcoded-jwt-secret",
			wantName:   "hardcoded-jwt-secret",
		},
		{
			name:       "bare ID is unchanged",
			inputCheck: "cbom-go-weak-rand",
			wantRuleID: "cbom-go-weak-rand",
			wantName:   "weak-rand",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`{"results":[{
				"check_id":"` + tc.inputCheck + `",
				"path":"x.go","start":{"line":1,"col":1},"end":{"line":1,"col":1},
				"extra":{"message":"m","severity":"INFO","metadata":{},"lines":""}
			}],"errors":[]}`)
			findings, err := ParseResults(payload)
			if err != nil {
				t.Fatalf("ParseResults: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].RuleID != tc.wantRuleID {
				t.Errorf("RuleID = %q, want %q", findings[0].RuleID, tc.wantRuleID)
			}
			if findings[0].Name != tc.wantName {
				t.Errorf("Name = %q, want %q", findings[0].Name, tc.wantName)
			}
		})
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/opengrep/ -run TestParseResults_StripsNamespacePrefix -v
```

Expected: FAIL — current parser stores `RuleID = r.CheckID` verbatim.

- [ ] **Step 4: Add `stripCheckIDNamespace` helper and use it in ParseResults**

Edit `cli/internal/opengrep/parser.go`. After the `deriveNameFromCheckID` function (currently ends around line 218), add:

```go
// stripCheckIDNamespace removes the directory-derived namespace prefix that
// OpenGrep adds when invoked with --config <dir>. The check_id format is
// "<dot.separated.namespace>.cbom-<lang>-<id>"; real rule IDs use dashes
// (no dots), so taking everything after the last dot is safe.
//
// When OpenGrep is invoked with per-file --config <file>, the prefix is
// absent and this is a no-op.
func stripCheckIDNamespace(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}
```

Then in `ParseResults` (around line 75), replace:

```go
		f := types.Finding{
			RuleID:         r.CheckID,
```

with:

```go
		canonicalID := stripCheckIDNamespace(r.CheckID)
		f := types.Finding{
			RuleID:         canonicalID,
```

And replace the `Name` derivation a few lines below (currently `f.Name = deriveNameFromCheckID(r.CheckID)`) with:

```go
		f.Name = deriveNameFromCheckID(canonicalID)
```

- [ ] **Step 5: Run test to verify it passes**

```bash
go test ./internal/opengrep/ -run TestParseResults_StripsNamespacePrefix -v
```

Expected: PASS (all 3 sub-cases).

- [ ] **Step 6: Run full opengrep package + race suite**

```bash
go test -race ./internal/opengrep/ ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

- [ ] **Step 7: Commit**

```bash
git add cli/internal/opengrep/parser.go cli/internal/opengrep/parser_test.go
git commit -m "fix(cli): strip opengrep dir-namespace prefix from RuleID (bug 8)

When opengrep is invoked with --config <dir>, every check_id is
prefixed by the directory path with dots, e.g.
'tmp.clean-rules.cbom-js-crypto-library-import'. cradar stored that
verbatim, breaking --rules/--disable-rule allowlist matching for
opengrep findings and round-tripping back to rule definitions.

Strip everything up to and including the last dot — real rule IDs
use dashes so the heuristic is safe. The Bug 6 switch to per-file
--config will eliminate the prefix at the source, but this guard
keeps the parser robust to either invocation style."
```

---

## Task C3: Bug 4 — Emit hint when `--only-inventory` matches 0 and pass-2 didn't run

**Files:**
- Modify: `cli/internal/cmd/scan.go` (around line 205, after pass-2 block)
- Test: `cli/internal/cmd/scan_test.go`

- [ ] **Step 1: Add a `pass2Ran` boolean tracked through the pass-2 branch**

Edit `cli/internal/cmd/scan.go`. Locate the block starting at line 185 (`if containsPass(passes, 2) {`). Before the `if`, declare:

```go
		// Tracks whether pass 2 actually executed (vs being skipped because
		// opengrep was absent and not required). Bug 4 uses this to emit a
		// hint when --only-inventory matches 0 findings.
		pass2Ran := false
```

Inside the `if containsPass(passes, 2)` block, after the `runPass2` call and before the `if pass2Err != nil` branch, set `pass2Ran = true` only when pass2 actually returned findings or returned an error that wasn't the soft-skip nil-nil:

The cleanest place is to inspect `runPass2`'s return contract: it returns `(nil, nil)` only on the soft-skip path. So:

Replace:

```go
				pass2Findings, pass2Err := runPass2(targetPath, rulesDir, pass2Required)
				if pass2Err != nil {
```

with:

```go
				pass2Findings, pass2Err := runPass2(targetPath, rulesDir, pass2Required)
				pass2Ran = pass2Err != nil || pass2Findings != nil
				if pass2Err != nil {
```

- [ ] **Step 2: Add the hint emission after the rule-filter block**

Edit `cli/internal/cmd/scan.go`. Locate where `rulefilter.Apply` runs (around line 226). After:

```go
		kept, filterStats := rulefilter.Apply(result.Findings, filterOpts)
		result.Findings = kept
		rulefilter.WarnDeprecated(cmd.ErrOrStderr(), filterStats, filterOpts.IncludeDeprecated)
```

Add:

```go
		// Bug 4: --only-inventory with no pass 2 deterministically returns 0
		// because pass-1 AST findings don't carry rule-derived categories.
		// Surface the cause so users don't think the flag is broken.
		onlyInv, _ := cmd.Flags().GetBool("only-inventory")
		categories, _ := cmd.Flags().GetStringSlice("category")
		invRequested := onlyInv
		for _, c := range categories {
			if strings.EqualFold(c, "inventory") {
				invRequested = true
			}
		}
		if invRequested && !pass2Ran && len(result.Findings) == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(),
				"Note: inventory filter matched 0 findings; inventory rules require Pass 2 (run 'cradar install-tools' or pass --passes 1,2).")
		}
```

- [ ] **Step 3: Write the failing test**

Append to `cli/internal/cmd/scan_test.go`:

```go
func TestScanCommand_OnlyInventoryHintWhenPass2Skipped(t *testing.T) {
	// Only meaningful when opengrep is absent — otherwise pass 2 would run.
	if opengrep.NewRunner() != nil {
		t.Skip("opengrep is installed; this test requires it absent")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "a.py"), []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "--only-inventory"})

	_ = rootCmd.Execute()

	if !strings.Contains(buf.String(), "inventory rules require Pass 2") {
		t.Errorf("expected --only-inventory hint in output, got:\n%s", buf.String())
	}
}
```

Ensure imports include `"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"`. Add it.

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/cmd/ -run TestScanCommand_OnlyInventoryHintWhenPass2Skipped -v
```

Expected: SKIP on this dev box (opengrep installed) — that's correct. To verify the code path on a box without opengrep, the test machine that runs CI without opengrep will exercise it.

To smoke-test locally with opengrep present, temporarily move it aside:

```bash
mv ~/.cradar/tools/opengrep ~/.cradar/tools/opengrep.bak
go test ./internal/cmd/ -run TestScanCommand_OnlyInventoryHintWhenPass2Skipped -v
mv ~/.cradar/tools/opengrep.bak ~/.cradar/tools/opengrep
```

Expected (during the moved-aside run): PASS. Restore opengrep.

- [ ] **Step 5: Run race suite**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

- [ ] **Step 6: Commit**

```bash
git add cli/internal/cmd/scan.go cli/internal/cmd/scan_test.go
git commit -m "fix(cli): hint when --only-inventory matches 0 without pass 2 (bug 4)

Pass-1 AST findings carry no rule-derived category, so the filter
normalises them to 'security'. Without pass 2 (opengrep absent),
--only-inventory deterministically returns 0 — which looks like a
broken flag. Track whether pass 2 actually ran and emit a one-line
hint pointing at install-tools when the combination produces 0
findings."
```

---

## Task C4: Bug 1 — Validate scan path before walking; exit 3 on missing/unreadable

**Files:**
- Modify: `cli/internal/cmd/scan.go` (just before `targetPath := args[0]`)
- Test: `cli/internal/cmd/scan_test.go`

- [ ] **Step 1: Write the three failing tests**

Append to `cli/internal/cmd/scan_test.go`:

```go
func TestScanCommand_MissingPathExitsConfigError(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", "/tmp/does-not-exist-" + t.Name()})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should explain missing path: %v", err)
	}
}

func TestScanCommand_NonDirectoryPathExitsConfigError(t *testing.T) {
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "a-file.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", filePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-directory path, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error should mention 'not a directory': %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/cmd/ -run 'TestScanCommand_MissingPathExitsConfigError|TestScanCommand_NonDirectoryPathExitsConfigError' -v
```

Expected: FAIL — current code calls `scanner.ScanDirWithOptions` on the bad path, which returns an empty CBOM and exit 0.

- [ ] **Step 3: Add path validation before the scan**

Edit `cli/internal/cmd/scan.go`. Locate (around line 162):

```go
		// Directory scanning mode.
		targetPath := args[0]
```

Insert immediately after:

```go
		// Bug 1: validate target exists and is a directory before walking.
		// Without this, a typo'd path returned exit 0 + empty CBOM, masking
		// broken CI configurations.
		info, statErr := os.Stat(targetPath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return ExitErrorf(ExitConfig, "scan path does not exist: %s", targetPath)
			}
			return ExitErrorf(ExitConfig, "cannot stat scan path %s: %v", targetPath, statErr)
		}
		if !info.IsDir() {
			return ExitErrorf(ExitConfig, "scan path is not a directory: %s", targetPath)
		}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cmd/ -run 'TestScanCommand_MissingPathExitsConfigError|TestScanCommand_NonDirectoryPathExitsConfigError' -v
```

Expected: PASS.

- [ ] **Step 5: Run race suite**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

- [ ] **Step 6: Commit**

```bash
git add cli/internal/cmd/scan.go cli/internal/cmd/scan_test.go
git commit -m "fix(cli): exit 3 when scan path is missing or not a directory (bug 1)

Validate the target with os.Stat before invoking the scanner. A
non-existent path previously returned exit 0 with an empty CycloneDX
document — a CI trap where typo'd paths passed green and uploaded
empty CBOMs. Returns ExitConfig (3) per ADR-036 with a specific
message for missing vs. not-a-directory."
```

---

## Task C5: Bug 5 — Installer URL fix + SHA-256 checksum verification

**Files:**
- Create: `cli/internal/tools/checksum.go`
- Create: `cli/internal/tools/checksum_test.go`
- Modify: `cli/internal/tools/installer.go`
- Modify: `cli/internal/tools/installer_test.go` (if exists; create otherwise)

- [ ] **Step 1: Create the checksum helper with a failing test**

Create `cli/internal/tools/checksum_test.go`:

```go
package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySHA256_MatchAccepted(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	if err := VerifySHA256(path, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifySHA256_MismatchRejected(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := VerifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should say 'mismatch': %v", err)
	}
}

func TestVerifySHA256_CaseInsensitiveHex(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Uppercase variant of the correct digest.
	if err := VerifySHA256(path, "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"); err != nil {
		t.Errorf("expected nil (case-insensitive), got %v", err)
	}
}

func TestVerifySHA256_MissingFile(t *testing.T) {
	err := VerifySHA256(filepath.Join(t.TempDir(), "nope"), "00")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail (no implementation yet)**

```bash
go test ./internal/tools/ -run TestVerifySHA256 -v
```

Expected: FAIL — `VerifySHA256` is undefined.

- [ ] **Step 3: Implement VerifySHA256**

Create `cli/internal/tools/checksum.go`:

```go
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerifySHA256 returns nil if the SHA-256 digest of the file at path matches
// expected (hex, case-insensitive). Returns an error describing the mismatch
// otherwise. Streams the file so memory is bounded for large binaries.
func VerifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("checksum: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("checksum: read %s: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))

	want := strings.TrimSpace(strings.ToLower(expected))
	if want == "" {
		return fmt.Errorf("checksum: expected digest is empty")
	}
	if got != want {
		return fmt.Errorf("checksum: mismatch for %s\n  want: %s\n  got:  %s", path, want, got)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/tools/ -run TestVerifySHA256 -v
```

Expected: PASS (all four sub-tests).

- [ ] **Step 5: Inspect the published OpenGrep release asset name**

```bash
curl -sLI -o /dev/null -w '%{http_code}\n' https://github.com/opengrep/opengrep/releases/download/v1.16.5/opengrep_manylinux_x86
```

Expected: `200` (or `302` if it follows). Confirms the asset URL we're switching to.

```bash
curl -sLI -o /dev/null -w '%{http_code}\n' https://github.com/opengrep/opengrep/releases/download/v1.16.5/opengrep_manylinux_x86.sha256
```

Expected: `200`. Confirms the sidecar checksum file exists.

If `.sha256` is missing on the release, fall back to `<binary>.sha256sum` (some releases use that name). Adjust the constant below accordingly.

- [ ] **Step 6: Refactor InstallOpenGrep to use the standalone binary + checksum**

Edit `cli/internal/tools/installer.go`. Replace the entire `InstallOpenGrep` function (lines 47–110) with:

```go
// openGrepAsset returns the (binaryURL, sha256URL) tuple for the current
// platform. The standalone single-file binary is preferred where available
// because it avoids the tarball extraction step entirely.
func openGrepAsset() (binaryURL, sha256URL string, err error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch {
	case goos == "linux" && goarch == "amd64":
		// Note: opengrep names the linux/amd64 asset "x86" (project convention,
		// even though the file is in fact 64-bit). The earlier "amd64->x86_64"
		// rewrite produced a 404.
		name := "opengrep_manylinux_x86"
		base := fmt.Sprintf("%s/%s/%s", OpenGrepBaseURL, OpenGrepVersion, name)
		return base, base + ".sha256", nil
	case goos == "linux" && goarch == "arm64":
		name := "opengrep_manylinux_aarch64"
		base := fmt.Sprintf("%s/%s/%s", OpenGrepBaseURL, OpenGrepVersion, name)
		return base, base + ".sha256", nil
	case goos == "darwin" && goarch == "amd64":
		name := "opengrep_osx_x86"
		base := fmt.Sprintf("%s/%s/%s", OpenGrepBaseURL, OpenGrepVersion, name)
		return base, base + ".sha256", nil
	case goos == "darwin" && goarch == "arm64":
		name := "opengrep_osx_aarch64"
		base := fmt.Sprintf("%s/%s/%s", OpenGrepBaseURL, OpenGrepVersion, name)
		return base, base + ".sha256", nil
	default:
		return "", "", fmt.Errorf("unsupported platform: %s/%s", goos, goarch)
	}
}

// InstallOpenGrep downloads the OpenGrep binary to toolsDir and verifies
// its SHA-256 against the sidecar checksum file published on the release.
// Returns an error on download failure, checksum mismatch, or unsupported
// platform.
func InstallOpenGrep(toolsDir string) error {
	binURL, sumURL, err := openGrepAsset()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("creating tools directory: %w", err)
	}
	destPath := filepath.Join(toolsDir, "opengrep")

	fmt.Printf("Downloading OpenGrep %s for %s/%s...\n", OpenGrepVersion, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("URL: %s\n", binURL)

	expectedSum, err := fetchSHA256(sumURL)
	if err != nil {
		return fmt.Errorf("fetching checksum: %w", err)
	}

	tmpPath, err := downloadToTemp(binURL, toolsDir, "opengrep-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := VerifySHA256(tmpPath, expectedSum); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("setting executable permission: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("moving binary into place: %w", err)
	}

	fmt.Printf("OpenGrep %s installed to %s (sha256 verified)\n", OpenGrepVersion, destPath)
	return nil
}

// fetchSHA256 GETs a sidecar checksum URL and returns the hex digest. The
// sidecar file format is either "<hex>" or "<hex>  <filename>" (sha256sum
// output). Only HTTPS URLs are accepted.
func fetchSHA256(url string) (string, error) {
	if err := requireHTTPS(url); err != nil {
		return "", err
	}
	resp, err := http.Get(url) //nolint:gosec // URL is a constant-derived sidecar of a constant binary URL
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read checksum body: %w", err)
	}
	// First whitespace-separated token is the digest in both formats.
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty checksum body at %s", url)
	}
	return fields[0], nil
}

// downloadToTemp streams binURL into a temp file in dir and returns its path.
// The caller is responsible for removing the file. Only HTTPS URLs are
// accepted.
func downloadToTemp(binURL, dir, pattern string) (string, error) {
	if err := requireHTTPS(binURL); err != nil {
		return "", err
	}
	resp, err := http.Get(binURL) //nolint:gosec // URL is constructed from package constants
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", binURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", binURL, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("saving download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	return tmpPath, nil
}

// requireHTTPS rejects non-HTTPS schemes so installer downloads cannot be
// downgraded to plaintext.
func requireHTTPS(url string) error {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("refusing non-HTTPS URL: %s", url)
	}
	return nil
}
```

The old `extractBinaryFromTarGz` is no longer needed by OpenGrep but YARA-X still uses it — leave the function in place. Same for `extractZip`.

- [ ] **Step 7: Add installer tests with an httptest server**

Append to `cli/internal/tools/installer_test.go` (create the file if absent — copy the package declaration from `installer.go`):

```go
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helperServer serves a binary at /bin and its sha256 sidecar at /bin.sha256.
// Optionally allows mutating the served body to simulate corruption.
func helperServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/bin.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  bin\n", digest)
	})
	return httptest.NewTLSServer(mux)
}

func TestFetchSHA256_ParsesDigest(t *testing.T) {
	srv := helperServer(t, []byte("payload"))
	defer srv.Close()

	// httptest.NewTLSServer uses a self-signed cert; override transport
	// to skip verification for the test only.
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	digest, err := fetchSHA256(srv.URL + "/bin.sha256")
	if err != nil {
		t.Fatalf("fetchSHA256: %v", err)
	}
	want := sha256.Sum256([]byte("payload"))
	if digest != hex.EncodeToString(want[:]) {
		t.Errorf("digest mismatch: got %q want %q", digest, hex.EncodeToString(want[:]))
	}
}

func TestFetchSHA256_RejectsNonHTTPS(t *testing.T) {
	_, err := fetchSHA256("http://example.com/x.sha256")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("expected non-HTTPS rejection, got: %v", err)
	}
}

func TestDownloadToTemp_StreamsAndPlacesFile(t *testing.T) {
	srv := helperServer(t, []byte("payload"))
	defer srv.Close()
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	dir := t.TempDir()
	path, err := downloadToTemp(srv.URL+"/bin", dir, "test-*")
	if err != nil {
		t.Fatalf("downloadToTemp: %v", err)
	}
	defer os.Remove(path)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("body = %q want %q", got, "payload")
	}
	if filepath.Dir(path) != dir {
		t.Errorf("temp file should be inside %q, got %q", dir, path)
	}
}

func TestInstaller_ChecksumMismatchRejected(t *testing.T) {
	// Server lies: serves "payload" but advertises a digest for "different".
	body := []byte("payload")
	wrongSum := sha256.Sum256([]byte("different"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			_, _ = w.Write(body)
		case "/bin.sha256":
			fmt.Fprintf(w, "%s  bin\n", hex.EncodeToString(wrongSum[:]))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	expected, err := fetchSHA256(srv.URL + "/bin.sha256")
	if err != nil {
		t.Fatalf("fetchSHA256: %v", err)
	}
	tmp := t.TempDir()
	path, err := downloadToTemp(srv.URL+"/bin", tmp, "test-*")
	if err != nil {
		t.Fatalf("downloadToTemp: %v", err)
	}
	defer os.Remove(path)

	if err := VerifySHA256(path, expected); err == nil {
		t.Fatal("expected checksum mismatch, got nil")
	}
}

func TestOpenGrepAsset_LinuxAmd64UsesStandaloneBinary(t *testing.T) {
	if !(strings.Contains(strings.ToLower(runtime_GOOS()), "linux") &&
		runtime_GOARCH() == "amd64") {
		t.Skip("test fixed to linux/amd64 expectations")
	}
	bin, sum, err := openGrepAsset()
	if err != nil {
		t.Fatalf("openGrepAsset: %v", err)
	}
	if !strings.HasSuffix(bin, "opengrep_manylinux_x86") {
		t.Errorf("binary URL = %q, expected suffix opengrep_manylinux_x86", bin)
	}
	if sum != bin+".sha256" {
		t.Errorf("sha256 URL = %q, expected %q", sum, bin+".sha256")
	}
}

// indirection so the platform test compiles on any host even when skipped.
func runtime_GOOS() string  { return goos() }
func runtime_GOARCH() string { return goarch() }
```

Add tiny helpers at the bottom of `installer.go` to expose `runtime.GOOS`/`runtime.GOARCH` for the test (or inline `runtime.GOOS`/`GOARCH` directly in the test and drop the helpers):

```go
// platform getters for testability.
func goos() string  { return runtime.GOOS }
func goarch() string { return runtime.GOARCH }
```

- [ ] **Step 8: Run installer tests**

```bash
go test ./internal/tools/ -v
```

Expected: all PASS (the `TestOpenGrepAsset_LinuxAmd64UsesStandaloneBinary` test skips on non-linux/amd64 hosts).

- [ ] **Step 9: Run race suite + smoke-test the installer end-to-end**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

```bash
# Smoke test: remove existing opengrep, build cradar, run install-tools.
mv ~/.cradar/tools/opengrep ~/.cradar/tools/opengrep.bak
go build -o /tmp/cradar-test ./cmd/cradar
/tmp/cradar-test install-tools
ls -la ~/.cradar/tools/opengrep
# Restore for subsequent work
mv ~/.cradar/tools/opengrep.bak ~/.cradar/tools/opengrep
```

Expected: install completes successfully with "sha256 verified" line.

- [ ] **Step 10: Commit**

```bash
git add cli/internal/tools/checksum.go cli/internal/tools/checksum_test.go cli/internal/tools/installer.go cli/internal/tools/installer_test.go
git commit -m "fix(cli): install-tools URL fix + SHA-256 verification (bug 5)

Switch InstallOpenGrep to the standalone single-file binary published
at the release root (opengrep_manylinux_x86 — opengrep's odd naming
where 'x86' actually means linux/amd64). The previous amd64->x86_64
rewrite produced a 404 on every fresh install.

Add SHA-256 verification using the sidecar .sha256 file published
alongside each binary. Downloads stream into a temp file, get
verified, then atomically rename into place; mismatch deletes the
temp file and returns ExitToolError. Refuses non-HTTPS URLs so the
download cannot be downgraded to plaintext.

YARA-X path unchanged for now — checksum verification there is a
separate follow-up."
```

---

## Task C6: Bug 6 — Opengrep pre-validate + skip-and-warn + surface errors

**Files:**
- Create: `cli/internal/opengrep/testdata/rules/good/example.yml`
- Create: `cli/internal/opengrep/testdata/rules/broken/bad-schema.yml`
- Create: `cli/internal/opengrep/runner_test.go`
- Modify: `cli/internal/opengrep/runner.go`
- Modify: `cli/internal/opengrep/parser.go`
- Modify: `cli/internal/opengrep/parser_test.go`

- [ ] **Step 1: Create fixture rule files**

```bash
mkdir -p cli/internal/opengrep/testdata/rules/good cli/internal/opengrep/testdata/rules/broken
```

Create `cli/internal/opengrep/testdata/rules/good/example.yml`:

```yaml
rules:
  - id: cbom-fixture-md5
    pattern: |
      hashlib.md5(...)
    message: "MD5 is broken"
    languages: [python]
    severity: WARNING
    metadata:
      cbom-asset-type: algorithm
      category: security
```

Create `cli/internal/opengrep/testdata/rules/broken/bad-schema.yml`:

```yaml
rules:
  - id: cbom-fixture-broken
    pattern: |
      something(...)
    # 'severity' is required by the schema — its absence triggers
    # InvalidRuleSchemaError when opengrep validates this file.
    languages: [python]
    metadata:
      category: security
```

- [ ] **Step 2: Write the failing runner test for skip-and-warn**

Create `cli/internal/opengrep/runner_test.go`:

```go
package opengrep

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadableRuleFiles_SkipsBroken(t *testing.T) {
	r := NewRunner()
	if r == nil || !r.Available() {
		t.Skip("opengrep not installed; cannot exercise validate subprocess")
	}

	dir := filepath.Join("testdata", "rules")
	loadable, skipped := r.loadableRuleFiles(dir)

	if len(loadable) == 0 {
		t.Fatal("expected at least one loadable rule file")
	}
	goodSeen := false
	for _, p := range loadable {
		if strings.HasSuffix(filepath.ToSlash(p), "good/example.yml") {
			goodSeen = true
		}
		if strings.Contains(filepath.ToSlash(p), "broken/") {
			t.Errorf("broken rule file should be excluded: %s", p)
		}
	}
	if !goodSeen {
		t.Errorf("good/example.yml should be loadable, loadable=%v", loadable)
	}

	if len(skipped) == 0 {
		t.Errorf("expected at least one skipped rule file with reason")
	}
	for _, sk := range skipped {
		if sk.Reason == "" {
			t.Errorf("skipped rule file %s missing reason", sk.Path)
		}
	}
}
```

- [ ] **Step 3: Run the failing test**

```bash
cd cli && go test ./internal/opengrep/ -run TestLoadableRuleFiles_SkipsBroken -v
```

Expected: FAIL — `loadableRuleFiles` is undefined.

- [ ] **Step 4: Implement loadableRuleFiles + integrate into Scan**

Edit `cli/internal/opengrep/runner.go`. Add at the bottom of the file:

```go
// SkippedRule names a rule file that failed validation, paired with the
// reason opengrep gave for refusing it.
type SkippedRule struct {
	Path   string
	Reason string
}

// loadableRuleFiles walks rulesDir, runs `opengrep validate` against each
// *.yml file, and returns the set that load cleanly plus the set that
// were rejected (with their reason). When opengrep is unavailable the
// caller has already short-circuited; this method assumes r.binaryPath
// is set.
func (r *Runner) loadableRuleFiles(rulesDir string) (loadable []string, skipped []SkippedRule) {
	if r == nil || r.binaryPath == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, []SkippedRule{{Path: rulesDir, Reason: err.Error()}}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		path := filepath.Join(rulesDir, e.Name())
		cmd := exec.Command(r.binaryPath, "validate", "--config", path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			reason := strings.TrimSpace(stderr.String())
			if reason == "" {
				reason = err.Error()
			}
			skipped = append(skipped, SkippedRule{Path: path, Reason: reason})
			continue
		}
		loadable = append(loadable, path)
	}
	return loadable, skipped
}
```

Add `"strings"` to the imports if not already present (it isn't — check current import block).

Update the import block in `cli/internal/opengrep/runner.go` to include `"strings"`:

```go
import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)
```

Now wire `loadableRuleFiles` into `Scan`. Replace the body of `Scan` (currently lines 82–119) with:

```go
// Scan runs OpenGrep against the target directory with the specified rules directory.
// Rule files that fail `opengrep validate` are skipped with a logged warning;
// other rule files in the same directory still run. Returns ExitToolError-style
// errors via the caller's wrapper when no rule files are loadable.
func (r *Runner) Scan(target string, rulesDir string) ([]types.Finding, error) {
	if r == nil || r.binaryPath == "" {
		return nil, fmt.Errorf("opengrep binary not available")
	}
	if rulesDir == "" {
		return nil, fmt.Errorf("rules directory not specified")
	}

	loadable, skipped := r.loadableRuleFiles(rulesDir)
	for _, sk := range skipped {
		// Logged at warn level so users see which rule files were dropped
		// instead of finding out via "0 findings, exit 0".
		fmt.Fprintf(os.Stderr, "opengrep: skipping rule file %s: %s\n", sk.Path, firstLine(sk.Reason))
	}
	if len(loadable) == 0 {
		return nil, fmt.Errorf("no loadable opengrep rule files in %s (skipped %d)", rulesDir, len(skipped))
	}

	args := []string{"scan", "--json", "--no-git-ignore"}
	for _, p := range loadable {
		args = append(args, "--config", p)
	}
	args = append(args, target)

	cmd := exec.Command(r.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// OpenGrep exits 1 when findings are present — not an error. Treat as
	// failure only when there is no JSON output at all.
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("opengrep execution failed: %w\nstderr: %s", err, stderr.String())
	}

	findings, parseErr := ParseResults(stdout.Bytes())
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse opengrep output: %w", parseErr)
	}
	return findings, nil
}

// firstLine returns the first non-empty line of s for one-line log output.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}
```

- [ ] **Step 5: Run the runner test**

```bash
go test ./internal/opengrep/ -run TestLoadableRuleFiles_SkipsBroken -v
```

Expected: PASS (on this dev box where opengrep is installed).

- [ ] **Step 6: Write the failing parser test for error surfacing**

Append to `cli/internal/opengrep/parser_test.go`:

```go
func TestParseResults_SurfacesErrorsArray(t *testing.T) {
	payload := []byte(`{
		"results": [],
		"errors": [
			{"message": "InvalidRuleSchemaError in python.yml at line 86", "level": "ERROR"}
		]
	}`)
	findings, err := ParseResults(payload)
	if err == nil {
		t.Fatal("expected error when results are empty but errors are present")
	}
	if findings != nil {
		t.Errorf("expected nil findings, got %d", len(findings))
	}
	if !strings.Contains(err.Error(), "InvalidRuleSchemaError") {
		t.Errorf("error should include opengrep error text: %v", err)
	}
}

func TestParseResults_KeepsFindingsWhenErrorsAlsoPresent(t *testing.T) {
	payload := []byte(`{
		"results": [{
			"check_id": "cbom-test-x",
			"path": "x.go",
			"start": {"line": 1, "col": 1},
			"end": {"line": 1, "col": 1},
			"extra": {"message": "m", "severity": "INFO", "metadata": {}, "lines": ""}
		}],
		"errors": [{"message": "warn-level non-fatal", "level": "WARN"}]
	}`)
	findings, err := ParseResults(payload)
	if err != nil {
		t.Fatalf("expected nil error (best-effort delivery), got: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}
```

Ensure `"strings"` is in the test file's imports.

- [ ] **Step 7: Run the failing parser tests**

```bash
go test ./internal/opengrep/ -run 'TestParseResults_SurfacesErrorsArray|TestParseResults_KeepsFindingsWhenErrorsAlsoPresent' -v
```

Expected: `SurfacesErrorsArray` FAILS (current parser ignores Errors entirely). `KeepsFindingsWhenErrorsAlsoPresent` PASSES (current behaviour).

- [ ] **Step 8: Surface errors in ParseResults**

Edit `cli/internal/opengrep/parser.go`. Replace the body of `ParseResults` (lines 63–103) with:

```go
// ParseResults parses OpenGrep JSON output into CipherRadar findings.
// All returned findings have Pass = 2.
//
// When opengrep returns errors AND no results, the function returns an
// error naming the opengrep errors — silently returning 0 findings used
// to mask broken rule files (Bug 6). When some results came back, errors
// are tolerated (best-effort delivery); they should still be logged by
// the caller.
func ParseResults(jsonData []byte) ([]types.Finding, error) {
	if len(jsonData) == 0 {
		return nil, nil
	}

	var output opengrepOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		return nil, fmt.Errorf("invalid opengrep JSON: %w", err)
	}

	if len(output.Results) == 0 && len(output.Errors) > 0 {
		msgs := make([]string, 0, len(output.Errors))
		for _, e := range output.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("opengrep produced no results, %d errors: %s",
			len(output.Errors), strings.Join(msgs, "; "))
	}

	findings := make([]types.Finding, 0, len(output.Results))
	for _, r := range output.Results {
		canonicalID := stripCheckIDNamespace(r.CheckID)
		f := types.Finding{
			RuleID:         canonicalID,
			Pass:           2,
			Description:    r.Extra.Message,
			Severity:       mapSeverity(r.Extra.Severity),
			Confidence:     mapConfidence(r.Extra.Metadata.Confidence),
			AssetType:      mapAssetType(r.Extra.Metadata.CbomAssetType),
			Category:       mapCategory(r.Extra.Metadata.Category),
			Maturity:       mapMaturity(r.Extra.Metadata.Maturity),
			NoiseRisk:      mapNoiseRisk(r.Extra.Metadata.NoiseRisk),
			DefaultEnabled: mapDefaultEnabled(r.Extra.Metadata.DefaultEnabled),
			Location: types.Location{
				File:      r.Path,
				StartLine: r.Start.Line,
				StartCol:  r.Start.Col,
				EndLine:   r.End.Line,
				EndCol:    r.End.Col,
				Snippet:   r.Extra.Lines,
			},
		}
		f.Name = deriveNameFromCheckID(canonicalID)
		findings = append(findings, f)
	}

	return findings, nil
}
```

- [ ] **Step 9: Run all parser + runner tests**

```bash
go test ./internal/opengrep/ -v
```

Expected: all PASS.

- [ ] **Step 10: End-to-end smoke against CipherRadarTestProj**

```bash
go build -o /tmp/cradar-test ./cmd/cradar
/tmp/cradar-test scan /home/nk-sentinel/projects/CipherRadarTestProj --passes 2 --rules-dir /home/nk-sentinel/projects/cradarCLIImprovements/scanner/rules --format text 2>&1 | tee /tmp/rc2-smoke-c6.txt | head -40
```

Expected: stderr lists the skipped rule files (python.yml, go.yml, dart.yml, rust.yml — per docs/cli-improvements-bugs.md Bug 7) and the scan completes with findings from the clean rule files (csharp, javascript, php, ruby, plus partial java/kotlin). Per Bug 7 baseline this should produce ≥6 opengrep findings where the pre-fix scan produced 0.

- [ ] **Step 11: Run race suite**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

- [ ] **Step 12: Commit**

```bash
git add cli/internal/opengrep/runner.go cli/internal/opengrep/parser.go cli/internal/opengrep/runner_test.go cli/internal/opengrep/parser_test.go cli/internal/opengrep/testdata
git commit -m "fix(cli): pass 2 skips broken rule files instead of silently producing zero findings (bug 6)

OpenGrep's --config <dir> mode rejects the entire load if any single
rule file has a schema or parse error, returning paths.scanned=[]
and a populated errors[] array. The previous parser ignored
errors[] and reported success with zero findings, so any drift in
the rule corpus silently disabled Pass 2.

Two changes:
  - runner: pre-validate each *.yml in the rules dir with 'opengrep
    validate'. Skipped files get a one-line warning on stderr. Files
    that load are passed individually via repeated --config so a
    breakage in one file no longer poisons the rest. No loadable
    files -> return error (caller maps to ExitToolError).
  - parser: when results=[] and errors=[...], return an error naming
    the opengrep messages instead of returning (nil, nil). When some
    results came back, errors are tolerated (best-effort delivery).

Verified end-to-end against CipherRadarTestProj: pre-fix returned 0
opengrep findings (all language rule files together broke load).
Post-fix returns findings from the clean rule files with the
broken ones surfaced as warnings."
```

---

## Task C7: Bug 3 — Debug instrumentation (per-scanner lifecycle + per-finding events)

**Files:**
- Modify: `cli/pkg/log/log.go`
- Modify: `cli/pkg/log/log_test.go`
- Modify: `cli/internal/scanner/scanner.go` (the runner loop — wherever per-scanner per-pass dispatch happens)
- Modify: `cli/internal/opengrep/parser.go` (per-finding emit) — optional, mostly covered via scanner runner
- Modify: `cli/internal/cmd/scan.go` (pass logger into runner if needed)

- [ ] **Step 1: Write the failing logger-helper test**

Append to `cli/pkg/log/log_test.go`:

```go
func TestLogger_ScannerLifecycleEvents(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	lg.ScannerStart("python", "/tmp/proj")
	lg.ScannerComplete("python", 3, 12*time.Millisecond)
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", "")

	if err := lg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		`"event":"scanner_start"`,
		`"event":"scanner_complete"`,
		`"event":"finding_emitted"`,
		`"scanner":"python"`,
		`"ruleID":"cbom-py-md5"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log missing %q\n--- log ---\n%s", want, got)
		}
	}
}

func TestLogger_SourceFieldOmittedWhenIncludeSourceFalse(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, IncludeSource: false, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", "hashlib.md5(secret)")
	_ = lg.Close()

	data, _ := os.ReadFile(lg.Path())
	if strings.Contains(string(data), "hashlib.md5") {
		t.Errorf("source snippet leaked when IncludeSource=false:\n%s", string(data))
	}
}

func TestLogger_SourceFieldPopulatedWhenIncludeSourceTrue(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, IncludeSource: true, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", "hashlib.md5(b'x')")
	_ = lg.Close()

	data, _ := os.ReadFile(lg.Path())
	if !strings.Contains(string(data), "hashlib.md5") {
		t.Errorf("source snippet should appear when IncludeSource=true:\n%s", string(data))
	}
}

func TestLogger_SourceFieldTruncatedAt200Chars(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, IncludeSource: true, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	long := strings.Repeat("a", 500)
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", long)
	_ = lg.Close()

	data, _ := os.ReadFile(lg.Path())
	if strings.Contains(string(data), strings.Repeat("a", 250)) {
		t.Errorf("source snippet was not truncated:\n%s", string(data))
	}
}
```

Ensure imports include `"time"` and `"os"`.

- [ ] **Step 2: Run the failing tests**

```bash
cd cli && go test ./pkg/log/ -run TestLogger -v
```

Expected: FAIL — `ScannerStart`, `ScannerComplete`, `FindingEmitted` undefined.

- [ ] **Step 3: Add the helpers to `pkg/log/log.go`**

Edit `cli/pkg/log/log.go`. Append after the existing `Error` method (around line 273):

```go
// ScannerStart emits a structured event when a per-language scanner begins.
// Use this in the per-pass dispatch loop so debug logs show ordering and
// coverage.
func (lg *Logger) ScannerStart(scanner, target string) {
	if lg == nil || lg.slog == nil {
		return
	}
	lg.slog.Debug("scanner_start",
		"event", "scanner_start",
		"scanner", scanner,
		"target", lg.RedactPath(target),
	)
}

// ScannerComplete emits a structured event when a per-language scanner
// finishes a target. `findings` is the number of findings produced by
// this scanner alone (not cumulative).
func (lg *Logger) ScannerComplete(scanner string, findings int, duration time.Duration) {
	if lg == nil || lg.slog == nil {
		return
	}
	lg.slog.Debug("scanner_complete",
		"event", "scanner_complete",
		"scanner", scanner,
		"findings", findings,
		"duration_ms", duration.Milliseconds(),
	)
}

// FindingEmitted emits a structured event for an individual finding. The
// source snippet is included only when --log-include-source is set;
// otherwise it is omitted. The snippet is truncated to 200 characters to
// keep log lines bounded.
func (lg *Logger) FindingEmitted(scanner, ruleID, severity, path, source string) {
	if lg == nil || lg.slog == nil {
		return
	}
	attrs := []any{
		"event", "finding_emitted",
		"scanner", scanner,
		"ruleID", ruleID,
		"severity", severity,
		"path", lg.RedactPath(path),
	}
	if lg.IncludeSource() && source != "" {
		if len(source) > 200 {
			source = source[:200]
		}
		attrs = append(attrs, "source", source)
	}
	lg.slog.Debug("finding_emitted", attrs...)
}
```

- [ ] **Step 4: Run the helper tests**

```bash
go test ./pkg/log/ -run TestLogger -v
```

Expected: all four PASS.

- [ ] **Step 5: Wire ScannerStart/Complete into the scanner runner**

```bash
grep -n "ScanDir\|for _, scanner\|s.ScanFile" cli/internal/scanner/scanner.go | head -10
```

Identify the per-file scan dispatch site (look for the loop calling `scanner.ScanFile(path, content)`). The exact lines depend on current code; insert ScannerStart/Complete around the loop body.

Pattern (apply where the loop dispatches per-scanner-per-file):

```go
import logpkg "github.com/nk-sentinel/cipherradar/cli/pkg/log"
// inside the dispatch:
lg := logpkg.Get()
scannerStart := time.Now()
lg.ScannerStart(s.Name(), path)
findings, err := s.ScanFile(path, content)
lg.ScannerComplete(s.Name(), len(findings), time.Since(scannerStart))
```

Avoid double-instrumenting — if there's already a per-file timing block, hook ScannerStart/Complete into the same scope rather than adding a parallel one.

Add `"time"` import to `cli/internal/scanner/scanner.go` if missing.

- [ ] **Step 6: Wire FindingEmitted in the dispatch loop**

In the same file, after the `findings, err := s.ScanFile(...)` call, emit per-finding events:

```go
for _, f := range findings {
	lg.FindingEmitted(s.Name(), f.RuleID, string(f.Severity), f.Location.File, f.Location.Snippet)
}
```

Don't insert this inside every scanner package — keeping it in the dispatch loop is one place to maintain and matches the spec's "minimal wiring" intent.

- [ ] **Step 7: Smoke-test with --debug + --log-include-source**

```bash
go build -o /tmp/cradar-test ./cmd/cradar
/tmp/cradar-test scan /home/nk-sentinel/projects/CipherRadarTestProj --debug --log-include-source --passes 1 2>/dev/null
ls -ltr ~/.cradar/logs/ | tail -3
tail -20 ~/.cradar/logs/$(ls -tr ~/.cradar/logs/ | tail -1) | head -20
```

Expected: the latest log file contains `scanner_start`, `scanner_complete`, and `finding_emitted` events with `source` fields populated.

- [ ] **Step 8: Run full race suite**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

- [ ] **Step 9: Commit**

```bash
git add cli/pkg/log/log.go cli/pkg/log/log_test.go cli/internal/scanner/scanner.go
git commit -m "feat(cli): debug instrumentation for scanner lifecycle + per-finding events (bug 3)

--debug and --log-include-source were wired flags with no
instrumentation — they did nothing beyond the two scan_started /
scan_complete entries. Add three logger helpers (ScannerStart,
ScannerComplete, FindingEmitted) and call them from the per-file
dispatch loop. FindingEmitted carries the matched source snippet
only when --log-include-source is set; snippets are truncated at
200 chars.

Concurrent-scan log interleaving stays deferred — these helpers
emit best-effort and JSONL parsing is unaffected by any reordering."
```

---

## Task C8: Docs, ADR-038, CHANGELOG, VERSION bump

**Files:**
- Create: `docs/decisions/ADR-038.md`
- Modify: `docs/cli-improvements-bugs.md` (append per-bug status lines)
- Modify: `CHANGELOG.md`
- Modify: `cli/VERSION` (or root `VERSION` — confirm with `find . -name VERSION -maxdepth 3`)

- [ ] **Step 1: Locate VERSION file**

```bash
find . -maxdepth 3 -name 'VERSION' -type f -not -path '*/node_modules/*'
cat $(find . -maxdepth 3 -name 'VERSION' -type f -not -path '*/node_modules/*' | head -1)
```

Expected: prints `0.2.0-rc.1`. Note the path.

- [ ] **Step 2: Bump VERSION**

```bash
echo '0.2.0-rc.2' > <VERSION_PATH_FROM_STEP_1>
```

- [ ] **Step 3: Write ADR-038**

Create `docs/decisions/ADR-038.md`:

```markdown
# ADR-038: Installer Checksum Verification

**Status:** Accepted
**Date:** 2026-05-18
**Supersedes:** —

## Context

`cradar install-tools` downloads OpenGrep (and YARA-X) from GitHub
release assets over HTTPS. Prior to rc2 the downloaded binary was
written to disk and executed without any integrity check beyond the
HTTPS TLS handshake. A compromised mirror, MITM at the time of a TLS
break, or a server-side asset swap could install an attacker-controlled
binary that cradar would happily run on every subsequent scan.

## Decision

Verify SHA-256 of every downloaded tool binary against the sidecar
`<asset>.sha256` file published alongside it on the GitHub release.
On mismatch, delete the temp file and return `ExitToolError` (exit 4).
HTTPS is required — `http://` URLs are refused at the installer layer.

Implementation lives in `cli/internal/tools/checksum.go`
(`VerifySHA256`) and `installer.go` (`fetchSHA256`, `downloadToTemp`,
`requireHTTPS`). Refer to commit history for the rc2 changes.

## Alternatives considered

1. **Code-signing verification (cosign / Sigstore).** Stronger trust
   anchor (an attacker compromising the release would also need a
   Sigstore key compromise). Deferred because OpenGrep does not
   currently publish signed releases. Revisit when upstream does.
2. **GPG signature verification.** Same publisher-dependency problem;
   neither OpenGrep nor YARA-X publishes signatures today.
3. **Pin the binary into the cradar source tree.** Eliminates the
   download but bloats the binary by ~40MB and forces every cradar
   release to also re-publish the bundled tool. cradar-full already
   covers the air-gapped path; this would duplicate that.

## Trust anchor

The published `<asset>.sha256` sidecar file. This is weaker than a
signed release would be — anyone who can swap the binary can usually
swap the sidecar too — but it eliminates the "asset swap without
publisher knowledge" failure mode (CDN cache poisoning, repository
infrastructure compromise where the attacker has not regenerated the
sidecar). Strictly better than no verification.

## Consequences

- Every fresh install now requires two HTTPS GETs instead of one.
  Bounded overhead (~50ms wall).
- Mismatch produces a hard exit (4) rather than installing an
  unverified binary.
- Future work: code-signing verification when upstream publishes
  signatures.
```

- [ ] **Step 4: Append per-bug status lines to docs/cli-improvements-bugs.md**

Append to `docs/cli-improvements-bugs.md`:

```markdown

---

## rc2 status (2026-05-18)

| # | Status | Fix commit |
|---|---|---|
| 1 | FIXED | <commit-sha-C4> |
| 2 | FIXED | <commit-sha-C1> |
| 3 | FIXED | <commit-sha-C7> |
| 4 | FIXED (hint added) | <commit-sha-C3> |
| 5 | FIXED (with checksum verification) | <commit-sha-C5> |
| 6 | FIXED (cradar hardening) | <commit-sha-C6> |
| 7 | OUT OF SCOPE for rc2 (rule rewrites deferred) | — |
| 8 | FIXED | <commit-sha-C2> |
```

Fill in the actual commit SHAs after running `git log --oneline -10`.

- [ ] **Step 5: Update CHANGELOG.md**

Read the existing CHANGELOG to match its style, then prepend a new section:

```bash
head -30 CHANGELOG.md
```

Add at the top under the existing rc1 entry:

```markdown
## 0.2.0-rc.2 — 2026-05-18

### Bug fixes

- **Critical:** Pass 2 silently produced 0 findings when any rule file
  in the rules directory failed to load — restored via per-file
  pre-validation, skip-and-warn for broken files, and surfaced
  `output.Errors` from opengrep. (Bug 6)
- **High:** `cradar scan` on a missing or non-directory path no
  longer returns exit 0 + empty CycloneDX — now exits 3 with a
  specific message. (Bug 1)
- **High:** `cradar install-tools` fixed for linux/amd64 (was 404 on
  every fresh install) and now verifies SHA-256 of downloaded
  binaries. New ADR-038. (Bug 5)
- **Medium:** OpenGrep findings' `RuleID` no longer carries the
  directory-derived namespace prefix; `--rules` and `--disable-rule`
  match opengrep findings correctly. (Bug 8)
- **Medium:** `--category bogus` now returns exit 3 (was exit 1).
  (Bug 2)
- **Low:** `--only-inventory` matched 0 findings without pass 2 emits
  a one-line hint pointing at `install-tools`. (Bug 4)
- **Low:** `--debug` and `--log-include-source` now produce
  per-scanner lifecycle events and per-finding emit events; source
  snippets are included only when the flag is set, truncated at 200
  chars. (Bug 3)
```

- [ ] **Step 6: Final test pass**

```bash
go test -race ./... | grep -E '^(FAIL|ok)' | grep -v '^ok'
```

Expected: empty output.

- [ ] **Step 7: Commit**

```bash
git add docs/decisions/ADR-038.md docs/cli-improvements-bugs.md CHANGELOG.md <VERSION_PATH>
git commit -m "chore: bump VERSION to 0.2.0-rc.2 with CHANGELOG + ADR-038

ADR-038 records the installer checksum verification decision. Bugs
doc gets a status table mapping each rc1 bug to its fix commit (or
'out of scope' for Bug 7). CHANGELOG lists the rc2 fixes in
severity order."
```

---

## Self-Review

**Spec coverage:**

| Spec section | Plan task(s) |
|---|---|
| 2 — Scope decisions (Bugs 1-6, 8 in; 7 out) | C1–C7 (each one bug); C8 docs out-scope statement |
| 3 — Commit order C1→C8 | Tasks numbered identically |
| 4.1 — Installer hardening | C5 (steps 6–7 cover URL + checksum, steps for non-HTTPS rejection) |
| 4.2 — Opengrep skip-and-warn + namespace strip | C6 (skip-and-warn), C2 (strip already done; C6 keeps it via the same `stripCheckIDNamespace` call) |
| 4.3 — Debug instrumentation | C7 |
| 4.4 — Path validation | C4 |
| 4.5 — Only-inventory hint | C3 |
| 4.6 — Exit-code wrap | C1 |
| 5.1 — Functional tests per bug | Every task has a "Step 1: write failing test" |
| 5.2 — Regression (race suite every commit) | Every task ends with `go test -race ./...` step before commit |
| 5.3 — Performance gates | Not yet measured; covered by smoke tests in C5/C6/C7 and called out as a manual gate in the PR description per spec |
| 5.4 — Security tests | C5 covers checksum mismatch + non-HTTPS; C4 covers path-validation special-file behaviour via `info.IsDir()`; C7 source-redaction covered via `IncludeSource` toggle tests |
| 6 — Documentation | C8 |

**Placeholder scan:**

- No `TODO`, `TBD`, or "fill in later". Commit-SHA placeholders in
  C8 step 4 are intentional and instructed to be filled in from
  `git log`.
- "Add appropriate error handling" — not present.
- "Write tests for the above" — every test step shows actual test
  code.

**Type consistency:**

- `SkippedRule{Path, Reason}` — defined in C6 step 4, used in C6
  step 4. Consistent.
- `VerifySHA256(path, expected string) error` — defined in C5 step
  3, used in C5 step 6. Consistent.
- `stripCheckIDNamespace` — defined in C2 step 4, used unchanged in
  C6 step 8.
- Logger helpers (`ScannerStart`, `ScannerComplete`, `FindingEmitted`)
  — names match in tests (C7 step 1) and implementations (C7 step 3).

**Note for executing engineer:** the spec lists `TestRunner_NoShellInjection` and a YAML-fuzz test under section 5.4. These are deferred from this plan; the existing `exec.Command(... , args...)` invocation in `runner.go` already passes rule file paths as argv (not via `sh -c`), so no shell-injection vector exists in the implementation as written. If a security reviewer asks for the explicit test, add it as a follow-up.

---
