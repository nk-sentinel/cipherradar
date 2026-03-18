// Package opengrep provides a subprocess integration for running OpenGrep
// (or compatible Semgrep) taint analysis as Pass 2 of the CipherRadar scan pipeline.
package opengrep

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Runner executes OpenGrep scans against a target directory.
type Runner struct {
	binaryPath string
}

// NewRunner creates a new OpenGrep runner.
// It searches for the opengrep binary in:
// 1. $CBOM_TOOLS_DIR/opengrep
// 2. ~/.cbom/tools/opengrep
// 3. $PATH (opengrep or semgrep -- opengrep is a drop-in replacement)
// Returns nil if no binary is found (Pass 2 will be skipped).
func NewRunner() *Runner {
	// 1. Check $CBOM_TOOLS_DIR/opengrep
	if toolsDir := os.Getenv("CBOM_TOOLS_DIR"); toolsDir != "" {
		candidate := filepath.Join(toolsDir, "opengrep")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 2. Check ~/.cbom/tools/opengrep
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".cbom", "tools", "opengrep")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 3. Check $PATH for opengrep only.
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
// Returns findings from the OpenGrep JSON output.
func (r *Runner) Scan(target string, rulesDir string) ([]types.Finding, error) {
	if r == nil || r.binaryPath == "" {
		return nil, fmt.Errorf("opengrep binary not available")
	}

	if rulesDir == "" {
		return nil, fmt.Errorf("rules directory not specified")
	}

	// Build the command: opengrep scan --config <rules-dir> --json --no-git-ignore <target>
	args := []string{
		"scan",
		"--config", rulesDir,
		"--json",
		"--no-git-ignore",
		target,
	}

	cmd := exec.Command(r.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// OpenGrep/Semgrep exits with code 1 when findings are present -- that is not an error.
	// Only treat it as an error if there is no JSON output at all.
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
