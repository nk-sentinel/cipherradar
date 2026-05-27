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

// PassAware is an optional interface a Scanner can implement to declare
// which detection pass it belongs to. The walker uses this when filtering
// universals against the `--passes` selection: a scanner that reports
// Pass 3 is skipped unless the user opted into Pass 3.
//
// Scanners that don't implement this interface are treated as Pass 1
// (run on every scan regardless of the passes selection) — that's the
// default for language scanners and the regex universal.
type PassAware interface {
	// Pass returns the pass number this scanner belongs to (1, 2, or 3).
	// 0 is reserved for "no pass affinity" — same effective behavior as
	// returning 1.
	Pass() int
}
