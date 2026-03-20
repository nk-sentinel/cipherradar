// Package joern provides a subprocess integration for running Joern
// inter-procedural taint analysis as Pass 3 of the CipherRadar scan pipeline.
package joern

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

//go:embed queries/*.sc
var queriesFS embed.FS

// Runner executes Joern scans against a target directory.
type Runner struct {
	binaryPath string
}

// NewRunner creates a new Joern runner.
// It searches for the joern binary in the following order:
//  1. Bundled next to the cradar binary (cradar-full scenario)
//  2. $CRADAR_TOOLS_DIR/joern
//  3. ~/.cradar/tools/joern
//  4. $PATH joern
//
// Returns nil if no binary is found (Pass 3 will be skipped).
func NewRunner() *Runner {
	// 1. Check next to the cradar binary itself (cradar-full bundles Joern here).
	if self, err := os.Executable(); err == nil {
		selfDir := filepath.Dir(self)
		candidate := filepath.Join(selfDir, "joern")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 2. Check $CRADAR_TOOLS_DIR/joern
	if toolsDir := os.Getenv("CRADAR_TOOLS_DIR"); toolsDir != "" {
		candidate := filepath.Join(toolsDir, "joern")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 3. Check ~/.cradar/tools/joern
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".cradar", "tools", "joern")
		if isExecutable(candidate) {
			return &Runner{binaryPath: candidate}
		}
	}

	// 4. Check $PATH for joern.
	if p, err := exec.LookPath("joern"); err == nil {
		return &Runner{binaryPath: p}
	}

	return nil
}

// Available returns true if the Joern binary is installed and executable.
func (r *Runner) Available() bool {
	return r != nil && r.binaryPath != ""
}

// BinaryPath returns the path to the Joern binary. Useful for diagnostics.
func (r *Runner) BinaryPath() string {
	if r == nil {
		return ""
	}
	return r.binaryPath
}

// Scan runs Joern against the target directory with the specified queries directory.
// If queriesDir is empty, embedded query scripts are extracted to a temporary directory.
// Returns findings from the Joern JSON output.
//
// The scan runs in two steps:
//  1. Export CPG: joern --script export-cpg.sc --param target=<path> --param output=<tmpdir>/cpg.bin
//  2. Run queries: joern --script <query>.sc --param cpg=<tmpdir>/cpg.bin
func (r *Runner) Scan(target string, queriesDir string) ([]types.Finding, error) {
	if r == nil || r.binaryPath == "" {
		return nil, fmt.Errorf("joern binary not available")
	}

	if target == "" {
		return nil, fmt.Errorf("target path not specified")
	}

	// Create a temporary directory for the CPG and working files.
	tmpDir, err := os.MkdirTemp("", "cradar-joern-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract embedded queries if no explicit directory provided.
	if queriesDir == "" {
		extractedDir, extractErr := ExtractQueriesToTempDir()
		if extractErr != nil {
			return nil, fmt.Errorf("extracting embedded queries: %w", extractErr)
		}
		defer os.RemoveAll(extractedDir)
		queriesDir = extractedDir
	}

	cpgPath := filepath.Join(tmpDir, "cpg.bin")

	// Step 1: Export CPG.
	if err := r.exportCPG(target, cpgPath); err != nil {
		return nil, fmt.Errorf("CPG export failed: %w", err)
	}

	// Step 2: Run query scripts against the CPG.
	queryFiles, err := filepath.Glob(filepath.Join(queriesDir, "*.sc"))
	if err != nil {
		return nil, fmt.Errorf("listing query scripts: %w", err)
	}

	var allFindings []types.Finding
	for _, queryFile := range queryFiles {
		findings, queryErr := r.runQuery(queryFile, cpgPath)
		if queryErr != nil {
			// Record the error but continue with other queries.
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// exportCPG runs Joern to generate a Code Property Graph for the target.
func (r *Runner) exportCPG(target string, cpgPath string) error {
	args := []string{
		"--script", "export-cpg.sc",
		"--param", fmt.Sprintf("target=%s", target),
		"--param", fmt.Sprintf("output=%s", cpgPath),
	}

	cmd := exec.Command(r.binaryPath, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("joern CPG export: %w\nstderr: %s", err, stderr.String())
	}

	return nil
}

// runQuery executes a single Joern query script against the CPG and returns findings.
func (r *Runner) runQuery(queryFile string, cpgPath string) ([]types.Finding, error) {
	args := []string{
		"--script", queryFile,
		"--param", fmt.Sprintf("cpg=%s", cpgPath),
	}

	cmd := exec.Command(r.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Joern may exit non-zero when findings are present — only treat as error
	// if there is no JSON output at all.
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("joern query %s failed: %w\nstderr: %s",
			filepath.Base(queryFile), err, stderr.String())
	}

	// Derive rule ID from query script filename (e.g., "crypto-key-flow.sc" -> "joern-crypto-key-flow").
	scriptName := filepath.Base(queryFile)
	ruleID := "joern-" + scriptName[:len(scriptName)-len(filepath.Ext(scriptName))]

	findings, parseErr := ParseResults(stdout.Bytes(), ruleID)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse joern output for %s: %w", scriptName, parseErr)
	}

	return findings, nil
}

// ExtractQueriesToTempDir writes all embedded query scripts to a temporary directory
// and returns the path. The caller is responsible for cleaning up the directory.
func ExtractQueriesToTempDir() (string, error) {
	entries, err := queriesFS.ReadDir("queries")
	if err != nil {
		return "", fmt.Errorf("reading embedded queries: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "cradar-joern-queries-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := queriesFS.ReadFile(filepath.Join("queries", entry.Name()))
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("reading embedded query %s: %w", entry.Name(), err)
		}
		outPath := filepath.Join(tmpDir, entry.Name())
		if err := os.WriteFile(outPath, content, 0644); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("writing query %s: %w", entry.Name(), err)
		}
	}

	return tmpDir, nil
}

// isExecutable returns true if the path exists and is executable.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0111 != 0
}
