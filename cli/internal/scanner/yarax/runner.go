// Package yarax provides a subprocess integration for running YARA-X (the
// `yr` binary) as Pass 3 of the CipherRadar scan pipeline. Pass 3 covers
// binary-content crypto detection — compiled libraries, executables, JVM
// class files, Python wheels, WASM modules, and OCI container layer
// contents. See ADR-039 for the motivating decision and the
// `docs/superpowers/specs/2026-05-24-yarax-binary-scanning-design.md`
// design spec for the four-sub-PR breakdown.
//
// Sub-PR A scope: discovery + per-file subprocess invocation + minimal JSON
// parsing. No embedded ruleset yet (that lands in Sub-PR B), no
// `--passes 3` flag wiring (Sub-PR C), no SHA-256 download verification
// (Sub-PR C). The runner soft-skips when `yr` is absent OR when the rules
// directory contains no `.yar` files — both states are expected during the
// gap between Sub-PR A and Sub-PR B.
package yarax

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/nk-sentinel/cipherradar/cli/internal/yararules"
)

// YARA-X per-file scan safety limits. These bound a single `yr` invocation so a
// pathological file (huge, or one that triggers a slow rule) can neither hang
// nor OOM the whole scan.
const (
	// yrSkipLargerBytes: files larger than this are skipped by yr (256 MB).
	yrSkipLargerBytes int64 = 256 << 20
	// yrScanTimeoutSecs: yr's own per-scan timeout (graceful abort).
	yrScanTimeoutSecs = 60
	// yrHardTimeout: wall-clock backstop enforced via CommandContext, set
	// above yrScanTimeoutSecs so yr's own timer normally fires first.
	yrHardTimeout = 90 * time.Second
)

// Runner executes YARA-X scans against individual target files.
//
// Per-file invocation (rather than per-directory) keeps path attribution
// trivial: each subprocess output references exactly the file that scanner
// dispatch handed us, mirroring how `walker.go` feeds the per-language
// scanners. Batching is a Sub-PR C optimisation if measurement warrants it.
type Runner struct {
	binaryPath string
}

// NewRunner discovers the `yr` binary using the same lookup order the
// OpenGrep runner uses (see cli/internal/opengrep/runner.go), and returns
// nil when none of the candidates resolve to an executable file. Returning
// nil — rather than an error — is intentional: callers can treat it as
// "Pass 3 unavailable" and either soft-skip (default) or hard-fail with
// ExitToolMissing (when the user explicitly asked for Pass 3 via flags,
// which is Sub-PR C scope).
//
// Lookup order:
//  1. Next to the cradar executable itself (cradar-full bundles `yr` here).
//  2. $CRADAR_TOOLS_DIR/yr
//  3. ~/.cradar/tools/yr
//  4. $PATH via exec.LookPath("yr")
func NewRunner() *Runner {
	// 1. Bundled next to the cradar binary (cradar-full layout).
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), "yr")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 2. $CRADAR_TOOLS_DIR/yr.
	if toolsDir := os.Getenv("CRADAR_TOOLS_DIR"); toolsDir != "" {
		candidate := filepath.Join(toolsDir, "yr")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 3. ~/.cradar/tools/yr (the install-tools default).
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".cradar", "tools", "yr")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 4. $PATH.
	if p, err := exec.LookPath("yr"); err == nil {
		return &Runner{binaryPath: p}
	}

	return nil
}

// NewRunnerWithBinary constructs a Runner pointing at an explicit binary
// path. Exported for tests so they can set up fake `yr` binaries in
// tempdirs without depending on the global lookup-order. Production code
// uses NewRunner.
func NewRunnerWithBinary(path string) *Runner {
	if !isExecutable(path) {
		return nil
	}
	return &Runner{binaryPath: path}
}

// Available reports whether the runner resolved a usable binary. A nil
// Runner is always unavailable so callers can use the typical
// `if r := NewRunner(); r.Available() { ... }` pattern.
func (r *Runner) Available() bool {
	return r != nil && r.binaryPath != ""
}

// BinaryPath returns the resolved `yr` path (or "" when the runner is
// nil / unresolved). Useful for diagnostic logging.
func (r *Runner) BinaryPath() string {
	if r == nil {
		return ""
	}
	return r.binaryPath
}

// RulesDir returns the directory the runner should load YARA-X rules
// from.
//
// Resolution order:
//  1. $CRADAR_YARA_RULES_DIR (when set) — caller-provided override,
//     used by tests and by users who want to scan with a custom or
//     extended ruleset.
//  2. The embedded starter ruleset, extracted to a tempdir once per
//     process (cli/internal/yararules.ExtractToTempDir). This is the
//     default path: the cradar binary ships with rules baked in via
//     //go:embed so a vanilla `cradar scan --passes 3` works without
//     any rule-file plumbing.
//
// Returns "" only when extraction fails (e.g. tempfs is full), in
// which case ScanFile soft-skips like the runner-absent path. The
// extraction is memoised in `embeddedRulesDir` so we don't pay the
// tempdir-create cost for every scanner invocation.
func RulesDir() string {
	if env := strings.TrimSpace(os.Getenv("CRADAR_YARA_RULES_DIR")); env != "" {
		return env
	}
	return ensureEmbeddedRulesDir()
}

// embeddedRulesDir is the once-extracted tempdir holding the embedded
// YARA-X starter ruleset. Populated lazily by ensureEmbeddedRulesDir
// the first time RulesDir is asked for a path with no env override.
// Process-scoped — the OS reclaims the tempdir at process exit, so
// no explicit cleanup is wired in (matches the cli/internal/rules
// pattern for OpenGrep).
var (
	embeddedRulesMu   sync.Mutex
	embeddedRulesDir  string
	embeddedRulesDone bool
)

// ensureEmbeddedRulesDir extracts the embedded ruleset on first call
// and returns the resulting tempdir path. Subsequent calls return the
// cached value. Returns "" when extraction fails; callers treat that
// as "no rules" and soft-skip. Guarded by a mutex (rather than sync.Once)
// so CleanupEmbeddedRules can reset it and a later scan re-extracts.
func ensureEmbeddedRulesDir() string {
	embeddedRulesMu.Lock()
	defer embeddedRulesMu.Unlock()
	if !embeddedRulesDone {
		embeddedRulesDone = true
		if dir, err := yararules.ExtractToTempDir(); err == nil {
			embeddedRulesDir = dir
		}
		// On failure leave embeddedRulesDir empty — soft-skip matches the
		// rest of the scanner's failure model.
	}
	return embeddedRulesDir
}

// ValidateRulesDir reports whether dir is usable as an external YARA-X rules
// directory: it must exist and contain at least one `.yar`/`.yara` file.
// Returns a descriptive error otherwise. Used to hard-fail an explicitly
// provided --yara-rules-dir instead of silently soft-skipping, mirroring the
// Pass-2 --rules-dir "error if no loadable rules" contract.
func ValidateRulesDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("empty rules directory")
	}
	has, err := dirContainsYaraRules(dir)
	if err != nil {
		return fmt.Errorf("reading YARA rules dir %q: %w", dir, err)
	}
	if !has {
		return fmt.Errorf("no .yar/.yara rule files found in %q", dir)
	}
	return nil
}

// yrScanArgs builds the `yr scan` argument list, including the safety guards
// (--skip-larger / --timeout / --no-mmap). Split out so the guards are unit
// testable without invoking the subprocess.
func yrScanArgs(rulesDir, target string) []string {
	return []string{
		"scan",
		"--output-format", "json",
		"--print-meta",
		"--print-strings",
		"--skip-larger", strconv.FormatInt(yrSkipLargerBytes, 10),
		"--timeout", strconv.Itoa(yrScanTimeoutSecs),
		"--no-mmap",
		rulesDir, target,
	}
}

// CleanupEmbeddedRules removes the extracted embedded-ruleset tempdir
// (/tmp/cradar-yara-rules-*) and resets the memo so a subsequent scan
// re-extracts. Previously this tempdir was created once per process and
// never removed, leaking on every Pass-3 run (gh #82). The scan command
// defers this after each scan. Safe to call when nothing was extracted.
func CleanupEmbeddedRules() {
	embeddedRulesMu.Lock()
	defer embeddedRulesMu.Unlock()
	if embeddedRulesDir != "" {
		_ = os.RemoveAll(embeddedRulesDir)
	}
	embeddedRulesDir = ""
	embeddedRulesDone = false
}

// Scan runs `yr scan --output-format json <rulesDir> <target>` against a
// single file and returns the parsed findings.
//
// Soft-skip cases — return (nil, nil) without invoking the subprocess:
//   - Runner is nil or unresolved (binary not installed). The per-file loop
//     stays trivial; the scan command surfaces one "pass 3 skipped: <reason>"
//     line after the walk (cmd/scan.go) so the skip is visible, not silent.
//   - rulesDir is empty (rules extraction failed / no external rules).
//   - rulesDir contains no `.yar` files (still no rules to load).
//
// Hard-fail cases — return an error:
//   - subprocess fails AND produced no JSON on stdout. YARA-X exits 0 even
//     when there are no matches, so a non-zero exit with empty stdout is a
//     real failure (binary blew up, rule file failed to compile, etc.).
//   - parser rejects the stdout (malformed JSON).
//
// Per-file invocation matches how walker.go dispatches to scanners; a
// batched mode is a future optimisation tracked in Sub-PR C.
func (r *Runner) Scan(target string, rulesDir string) ([]types.Finding, error) {
	if r == nil || r.binaryPath == "" {
		// Soft-skip: no binary. The per-file loop stays quiet; cmd/scan.go
		// emits a single "pass 3 skipped: yara-x not found" line after the walk.
		return nil, nil
	}
	if rulesDir == "" {
		return nil, nil
	}
	hasRules, err := dirContainsYaraRules(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("yarax: scanning rules dir %s: %w", rulesDir, err)
	}
	if !hasRules {
		// Soft-skip: rules directory is present but empty (Sub-PR A
		// state — no rules ship yet). Returning nil here lets the
		// scanner be registered without erroring on every binary.
		return nil, nil
	}

	// Pass-3 invocation. We request --print-meta and --print-strings so
	// the JSON envelope carries the cbom_primitive/cbom_asset_type meta
	// the canonicalize pass needs, plus the offset/snippet location data
	// the binary-finding location helper formats.
	//
	// Safety guards (a pathological file must not hang or OOM the scan):
	//   --skip-larger: skip files above the size cap (YARA-X scan cost scales
	//     linearly with file size, so multi-GB blobs are slow regardless).
	//   --timeout: abort a single-file scan that runs too long.
	//   --no-mmap: read the file into a buffer instead of memory-mapping it —
	//     avoids a SIGBUS if the (extracted/temp) file is truncated mid-scan.
	// A CommandContext deadline backstops --timeout in case yr wedges before
	// its own timer fires.
	ctx, cancel := context.WithTimeout(context.Background(), yrHardTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.binaryPath, yrScanArgs(rulesDir, target)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("yarax: yr timed out after %s scanning %s", yrHardTimeout, target)
	}
	// YARA-X exits 0 on success even when no matches were found, so a
	// non-zero exit with empty stdout is a real failure. Mirror the
	// OpenGrep runner's "tolerate non-zero when we have JSON" pattern.
	if runErr != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("yarax: yr execution failed: %w\nstderr: %s", runErr, stderr.String())
	}

	findings, parseErr := ParseResults(stdout.Bytes(), target)
	if parseErr != nil {
		return nil, fmt.Errorf("yarax: parsing yr output: %w", parseErr)
	}
	return findings, nil
}

// dirContainsYaraRules walks rulesDir non-recursively first, then
// recursively if needed, to detect at least one `.yar` or `.yara` file.
// Returns false when the directory is missing — callers map that to a
// soft-skip rather than an error (matches the "no rules available" UX).
func dirContainsYaraRules(rulesDir string) (bool, error) {
	info, err := os.Stat(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() {
		// A non-directory path can't host a rule corpus; treat as
		// "no rules" rather than failing.
		return false, nil
	}
	var found bool
	walkErr := filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext == ".yar" || ext == ".yara" {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return false, walkErr
	}
	return found, nil
}

// isExecutable returns true when path resolves to an existing,
// non-directory file with at least one execute bit set.
func isExecutable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path) // #nosec G703 -- path is the resolved tool-binary location (next-to-exe / CRADAR_TOOLS_DIR / ~/.cradar/tools / $PATH), operator-controlled and not derived from scanned input; stat-only, no traversal
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0o111 != 0
}
