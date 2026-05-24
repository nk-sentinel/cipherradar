// Package yararules embeds the YARA-X starter ruleset shipped with the
// cradar binary. The .yar files in data/ are copied from
// scanner/yara-rules/ (the single source of truth) via go generate; do
// not edit them directly.
//
// At runtime the rules are written to a temp dir because YARA-X's
// command-line scanner takes a filesystem path, not a byte slice.
package yararules

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:generate sh -c "cp ../../../scanner/yara-rules/*.yar data/"

//go:embed data/*.yar
var rulesFS embed.FS

// ExtractToTempDir writes every embedded .yar rule file to a fresh
// temporary directory and returns its path. The caller owns the
// directory and is responsible for cleaning it up via os.RemoveAll.
func ExtractToTempDir() (string, error) {
	entries, err := rulesFS.ReadDir("data")
	if err != nil {
		return "", fmt.Errorf("reading embedded yara rules: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "cradar-yara-rules-*")
	if err != nil {
		return "", fmt.Errorf("creating yara rules temp dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := rulesFS.ReadFile(filepath.Join("data", entry.Name()))
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("reading embedded yara rule %s: %w", entry.Name(), err)
		}
		outPath := filepath.Join(tmpDir, entry.Name())
		if err := os.WriteFile(outPath, content, 0o644); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("writing yara rule %s: %w", entry.Name(), err)
		}
	}

	return tmpDir, nil
}

// ReadFile returns the raw .yar content for a single embedded rule file
// by base name (e.g. "openssl-versions.yar"). Useful for callers (tests,
// canonicalize sanity checks) that need to inspect rule metadata
// without extracting every file to disk.
func ReadFile(name string) ([]byte, error) {
	return rulesFS.ReadFile(filepath.Join("data", name))
}

// RuleFiles returns the base names of every embedded .yar rule file.
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
