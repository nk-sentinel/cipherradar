package scanner

import (
	"path/filepath"
	"strings"
)

// DetectLanguage returns the file extension (lowercased, with dot) for a given file path.
// Returns empty string if the extension is not recognized.
func DetectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return ext
}
