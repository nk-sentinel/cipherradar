package binary

import (
	"bytes"
	"fmt"
	"sync/atomic"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// BinaryScanner detects cryptographic constants in compiled binaries by
// searching for well-known byte patterns (S-boxes, round constants, OIDs).
type BinaryScanner struct{}

// New creates a new BinaryScanner instance.
func New() *BinaryScanner {
	return &BinaryScanner{}
}

// Name returns the scanner's name.
func (s *BinaryScanner) Name() string {
	return "binary"
}

// Extensions returns the file extensions this scanner handles.
func (s *BinaryScanner) Extensions() []string {
	return []string{
		".so", ".dll", ".dylib", ".exe", ".class",
	}
}

// archiveExtensions are handled by the archive-specific scanners (JAR, wheel)
// and registered separately.
var archiveExtensions = map[string]bool{
	".jar": true, ".war": true, ".ear": true,
	".whl": true, ".egg": true,
}

// ScanFile scans a binary file's raw bytes for known crypto constant patterns.
func (s *BinaryScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	return scanBytes(path, content), nil
}

// scanBytes runs all crypto patterns against the given data and returns findings.
// It is shared between the direct binary scanner and the archive handlers.
// Findings are tagged with Category/Maturity via scanner.AnnotateFindings so
// they're not silently dropped by --only-inventory / --only-security filters.
func scanBytes(path string, data []byte) []types.Finding {
	var findings []types.Finding

	// De-duplicate: if we already found a family via one pattern, skip others
	// in the same family to avoid noisy output.
	seen := make(map[string]bool)

	for i := range cryptoPatterns {
		pat := &cryptoPatterns[i]
		if seen[pat.Family+"|"+pat.Primitive] {
			continue
		}

		offset := findPattern(data, pat.Bytes, pat.MinMatch)
		if offset < 0 {
			continue
		}

		seen[pat.Family+"|"+pat.Primitive] = true

		qi := quantum.GetInfo(pat.Family)
		severity := patternSeverity(pat.Family)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       pat.Name,
			Location:   binaryLocation(path, offset, pat.Name),
			Severity:   severity,
			Confidence: types.ConfidenceMedium,
			Properties: types.CryptoProperties{
				Primitive:        pat.Primitive,
				AlgorithmFamily:  pat.Family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
			},
			Description: fmt.Sprintf("Crypto constant %q detected in binary at offset 0x%x", pat.Name, offset),
			RuleID:      fmt.Sprintf("cbom-binary-%s", pat.Family),
			Pass:        1,
		})
	}

	return scanner.AnnotateFindings(findings)
}

// findPattern searches for at least minMatch consecutive bytes of pattern
// within data. Returns the offset of the first match, or -1 if not found.
//
// The implementation uses a simplified Boyer-Moore-Horspool bad-character
// shift table on the first minMatch bytes of the pattern, which provides
// sub-linear average performance on large binary files.
func findPattern(data, pattern []byte, minMatch int) int {
	if minMatch <= 0 || minMatch > len(pattern) {
		minMatch = len(pattern)
	}
	needle := pattern[:minMatch]
	n := len(data)
	m := len(needle)
	if m == 0 || n < m {
		return -1
	}

	// Build bad-character shift table (Horspool variant).
	var shift [256]int
	for i := range shift {
		shift[i] = m
	}
	for i := 0; i < m-1; i++ {
		shift[needle[i]] = m - 1 - i
	}

	// Scan.
	i := 0
	for i <= n-m {
		if bytes.Equal(data[i:i+m], needle) {
			return i
		}
		i += shift[data[i+m-1]]
	}

	return -1
}

// binaryLocation creates a Location for a finding within a binary file.
// Binary files don't have meaningful line numbers, so we encode the byte offset.
func binaryLocation(path string, offset int, patternName string) types.Location {
	return types.Location{
		File:      path,
		StartLine: 0,
		StartCol:  offset,
		EndLine:   0,
		EndCol:    offset,
		Snippet:   fmt.Sprintf("[binary] %s at offset 0x%x", patternName, offset),
	}
}

// patternSeverity maps algorithm families to appropriate severity levels
// for binary detection.
func patternSeverity(family string) types.Severity {
	switch family {
	case "des", "md5", "rc4":
		return types.SeverityHigh
	case "sha1":
		return types.SeverityHigh
	case "blowfish":
		return types.SeverityMedium
	default:
		return types.SeverityInfo
	}
}

func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("BIN-%d", id)
}
