// Package opengrep provides a subprocess integration for running OpenGrep
// taint analysis as Pass 2 of the CipherRadar scan pipeline.
package opengrep

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Runner executes OpenGrep scans against a target directory.
type Runner struct {
	binaryPath string
}

// NewRunner creates a new OpenGrep runner.
// It searches for the opengrep binary in the following order:
//  1. Bundled next to the cradar binary (cradar-full scenario)
//  2. $CRADAR_TOOLS_DIR/opengrep
//  3. ~/.cradar/tools/opengrep
//  4. $PATH opengrep
//
// Returns nil if no binary is found (Pass 2 will be skipped).
func NewRunner() *Runner {
	// 1. Check next to the cradar binary itself (cradar-full bundles OpenGrep here).
	// This ensures cradar-full always uses its own bundled version,
	// regardless of any system-installed OpenGrep.
	if self, err := os.Executable(); err == nil {
		selfDir := filepath.Dir(self)
		candidate := filepath.Join(selfDir, "opengrep")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 2. Check $CRADAR_TOOLS_DIR/opengrep
	if toolsDir := os.Getenv("CRADAR_TOOLS_DIR"); toolsDir != "" {
		candidate := filepath.Join(toolsDir, "opengrep")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 3. Check ~/.cradar/tools/opengrep
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".cradar", "tools", "opengrep")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 4. Check $PATH for opengrep only.
	// Do NOT fall back to semgrep — Semgrep moved taint analysis to their
	// commercial tier (Dec 2024). OpenGrep (fork of Semgrep v1.100.0) restores
	// taint mode under LGPL-2.1. See ADR-009.
	if p, err := exec.LookPath("opengrep"); err == nil {
		return &Runner{binaryPath: p}
	}

	return nil
}

// Available returns true if the OpenGrep binary is installed and executable.
func (r *Runner) Available() bool {
	return r != nil && r.binaryPath != ""
}

// BinaryPath returns the path to the OpenGrep binary. Useful for diagnostics.
func (r *Runner) BinaryPath() string {
	if r == nil {
		return ""
	}
	return r.binaryPath
}

// Scan runs OpenGrep against the target directory with the specified rules directory.
// Rule files that fail `opengrep validate` are skipped with a logged warning;
// other rule files in the same directory still run. Returns an error when no
// rule files are loadable, when opengrep itself fails to produce any output,
// or when opengrep returns no results but reports errors (see Bug 6).
func (r *Runner) Scan(target string, rulesDir string) ([]types.Finding, error) {
	if r == nil || r.binaryPath == "" {
		return nil, fmt.Errorf("opengrep binary not available")
	}
	if rulesDir == "" {
		return nil, fmt.Errorf("rules directory not specified")
	}

	loadable, skipped := r.loadableRuleFiles(rulesDir)
	for _, sk := range skipped {
		// Surface which rule files were dropped so users see why pass 2
		// coverage shrank instead of finding out via "0 findings, exit 0".
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

// isExecutable returns true if the path exists and is executable.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0111 != 0
}

// SkippedRule names a rule file that failed validation, paired with the
// reason opengrep gave for refusing it.
type SkippedRule struct {
	Path   string
	Reason string
}

// loadableRuleFiles runs a single `opengrep validate <rulesDir>` (recursive),
// parses its output to identify rule files that failed to load, and returns
// the set that load cleanly plus the set that were rejected. Walks rulesDir
// for the list of *.yml files; anything not flagged in opengrep's output is
// considered loadable.
//
// Performance: one subprocess regardless of file count (the original C6
// implementation invoked N subprocesses sequentially, costing ~5.5s on a
// 12-file rule set).
func (r *Runner) loadableRuleFiles(rulesDir string) (loadable []string, skipped []SkippedRule) {
	if r == nil || r.binaryPath == "" {
		return nil, nil
	}

	// Enumerate all *.yml files in the dir tree first; we need the full set
	// to compute (loadable = all - broken).
	allFiles := make(map[string]struct{})
	walkErr := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			skipped = append(skipped, SkippedRule{Path: path, Reason: err.Error()})
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".yml") {
			return nil
		}
		abs, absErr := filepath.Abs(path)
		if absErr != nil {
			abs = path
		}
		allFiles[abs] = struct{}{}
		return nil
	})
	if walkErr != nil {
		skipped = append(skipped, SkippedRule{Path: rulesDir, Reason: walkErr.Error()})
	}
	if len(allFiles) == 0 {
		return nil, skipped
	}

	// Single dir-validate subprocess. Output goes to stderr+stdout; we
	// combine and parse [WARNING]: lines.
	cmd := exec.Command(r.binaryPath, "validate", rulesDir)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	_ = cmd.Run() // exit code 0 even when some rules are invalid; ignore.

	brokenFiles := parseValidateBrokenFiles(combined.String())

	for absPath := range allFiles {
		if reason, isBroken := brokenFiles[absPath]; isBroken {
			skipped = append(skipped, SkippedRule{Path: absPath, Reason: reason})
		} else {
			loadable = append(loadable, absPath)
		}
	}
	// Stable order so callers / logs aren't flaky.
	sort.Strings(loadable)
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	return loadable, skipped
}

// parseValidateBrokenFiles extracts {filepath: reason} from opengrep validate
// output. The output format (v1.16.5) emits one line per invalid rule of the
// form:
//
//	[WARNING]: invalid rule <rule-id>, <abs-or-rel-path>.yml:<line>:<col>: <reason>
//
// ANSI color codes and chardet/locale warnings are stripped/ignored. When
// the same file has multiple bad rules, only the first reason is recorded
// (keeps the map small; full output remains available in the log).
func parseValidateBrokenFiles(output string) map[string]string {
	broken := make(map[string]string)
	// Match the WARNING + invalid rule pattern. Capture the file path
	// (anything ending in .yml) and the trailing reason text.
	re := regexp.MustCompile(`invalid rule [^,]+, (\S+\.yml):\d+:\d+: (.+)`)
	for _, raw := range strings.Split(output, "\n") {
		line := stripANSI(raw)
		m := re.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		path := m[1]
		// Normalize to absolute path so the map keys match allFiles' keys.
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if _, seen := broken[path]; !seen {
			broken[path] = strings.TrimSpace(m[2])
		}
	}
	return broken
}

// stripANSI removes ANSI color/escape sequences that opengrep emits when its
// output is not redirected. The pattern matches common CSI sequences (ESC [
// followed by parameters and a final byte in the @-~ range).
func stripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[@-~]`)

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
