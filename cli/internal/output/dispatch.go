package output

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FormatFromPath returns the registered output format implied by a file
// name's extension. Unknown extensions return an empty string; callers
// should fall back to the `--format` flag or the built-in default.
//
// `.sonar.json` is handled before `.json` so SonarQube reports don't get
// mis-dispatched to the CycloneDX writer.
func FormatFromPath(path string) string {
	if path == "" {
		return ""
	}
	lower := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(lower))
	switch {
	case strings.HasSuffix(base, ".sonar.json"):
		return "sonarqube-generic"
	case strings.HasSuffix(base, ".cbom.json"),
		strings.HasSuffix(base, ".cdx.json"),
		strings.HasSuffix(base, ".cyclonedx.json"):
		return "cyclonedx-json"
	}
	switch filepath.Ext(lower) {
	case ".json":
		return "cyclonedx-json"
	case ".sarif":
		return "sarif"
	case ".pdf":
		return "pdf"
	case ".txt", ".text":
		return "text"
	}
	return ""
}

// SupportedFormats lists every writer WriterFactory can build. Used by
// help text so additions stay in sync.
func SupportedFormats() []string {
	return []string{
		"cyclonedx-json",
		"sarif",
		"text",
		"pdf",
		"sonarqube-generic",
	}
}

// ResolveOutputFormat decides which format a given output file should use
// following the documented precedence order:
//
//   1. Explicit format override from the caller (e.g. `--format` when
//      there is exactly one output sink).
//   2. File extension dispatch (`cbom.json` → cyclonedx-json, etc.).
//   3. Config-file default (`cfg.Format` from .cradar.yml).
//   4. Built-in fallback.
//
// An empty return value means the caller should error out.
func ResolveOutputFormat(path, explicit, cfgDefault, fallback string) string {
	if explicit != "" {
		return explicit
	}
	if f := FormatFromPath(path); f != "" {
		return f
	}
	if cfgDefault != "" {
		return cfgDefault
	}
	return fallback
}

// ValidateFormat returns an error if fmtName is not a registered writer.
// Kept separate from WriterFactory so callers can validate configuration
// without having to instantiate a writer.
func ValidateFormat(fmtName string) error {
	for _, f := range SupportedFormats() {
		if f == fmtName {
			return nil
		}
	}
	return fmt.Errorf("unsupported output format: %q (supported: %s)",
		fmtName, strings.Join(SupportedFormats(), ", "))
}
