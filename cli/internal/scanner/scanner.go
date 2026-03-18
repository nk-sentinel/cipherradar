package scanner

import "github.com/nk-sentinel/cipherradar/cli/internal/types"

// Scanner is the interface that all language-specific scanners must implement.
type Scanner interface {
	// Name returns the scanner's language name (e.g. "python", "java").
	Name() string

	// Extensions returns the file extensions this scanner handles (e.g. [".py", ".pyw"]).
	Extensions() []string

	// ScanFile scans a single file's content and returns findings.
	// path is the relative file path from the scan root.
	// content is the raw file bytes.
	ScanFile(path string, content []byte) ([]types.Finding, error)
}
