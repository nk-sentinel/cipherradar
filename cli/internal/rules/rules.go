// Package rules provides embedded OpenGrep/Semgrep YAML rules for Pass 2 taint analysis.
//
// The YAML files in data/ are copied from scanner/rules/ (the single source of truth).
// Run "go generate ./internal/rules" to sync them.
package rules

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:generate sh -c "cp ../../../scanner/rules/*.yml data/"

//go:embed data/*.yml
var rulesFS embed.FS

// ExtractToTempDir writes all embedded rule files to a temporary directory
// and returns the path. The caller is responsible for cleaning up the directory.
func ExtractToTempDir() (string, error) {
	entries, err := rulesFS.ReadDir("data")
	if err != nil {
		return "", fmt.Errorf("reading embedded rules: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "cbom-rules-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := rulesFS.ReadFile(filepath.Join("data", entry.Name()))
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("reading embedded rule %s: %w", entry.Name(), err)
		}
		outPath := filepath.Join(tmpDir, entry.Name())
		if err := os.WriteFile(outPath, content, 0644); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("writing rule %s: %w", entry.Name(), err)
		}
	}

	return tmpDir, nil
}

// RuleFiles returns the names of all embedded rule files.
func RuleFiles() ([]string, error) {
	entries, err := rulesFS.ReadDir("data")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
