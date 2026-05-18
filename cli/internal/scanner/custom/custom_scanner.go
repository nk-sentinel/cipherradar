// Package custom provides a scanner that detects calls to user-defined
// cryptographic wrapper functions as specified in .cradar.yml custom_wrappers.
package custom

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/nk-sentinel/cipherradar/cli/internal/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is an atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// CustomScanner detects calls to user-defined cryptographic wrapper functions.
// It matches function call patterns by name against source file content using
// simple string matching (language-aware).
type CustomScanner struct {
	wrappers []config.CustomWrapper
}

// New creates a new CustomScanner with the given wrapper definitions.
// Returns nil if no wrappers are defined.
func New(wrappers []config.CustomWrapper) *CustomScanner {
	if len(wrappers) == 0 {
		return nil
	}
	return &CustomScanner{wrappers: wrappers}
}

// Name returns the scanner's name.
func (s *CustomScanner) Name() string {
	return "custom"
}

// Extensions returns an empty slice — the custom scanner is dispatched
// by the orchestrator based on file language, not extension.
func (s *CustomScanner) Extensions() []string {
	return nil
}

// ScanFile scans a source file for calls to the configured custom wrapper
// functions. Only wrappers matching the file's language are checked.
func (s *CustomScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 || len(s.wrappers) == 0 {
		return nil, nil
	}

	lang := detectLanguageFromPath(path)
	if lang == "" {
		return nil, nil
	}

	lines := strings.Split(string(content), "\n")
	var findings []types.Finding

	for i := range s.wrappers {
		w := &s.wrappers[i]

		// Only match wrappers for this file's language.
		if !strings.EqualFold(w.Language, lang) {
			continue
		}

		// Derive the function call pattern to search for.
		callPatterns := callPatternsForWrapper(w)

		for lineNum, line := range lines {
			for _, pattern := range callPatterns {
				if strings.Contains(line, pattern) {
					findings = append(findings, buildFinding(w, path, lineNum+1, strings.TrimSpace(line)))
					break // one finding per line per wrapper
				}
			}
		}
	}

	return scanner.AnnotateFindings(findings), nil
}

// ScanFileForLanguage scans a source file for calls to custom wrappers
// matching the specified language. This is used by the orchestrator to
// dispatch the custom scanner alongside the language-specific scanner.
func (s *CustomScanner) ScanFileForLanguage(path string, content []byte, lang string) ([]types.Finding, error) {
	if len(content) == 0 || len(s.wrappers) == 0 {
		return nil, nil
	}

	lines := strings.Split(string(content), "\n")
	var findings []types.Finding

	for i := range s.wrappers {
		w := &s.wrappers[i]

		if !strings.EqualFold(w.Language, lang) {
			continue
		}

		callPatterns := callPatternsForWrapper(w)

		for lineNum, line := range lines {
			for _, pattern := range callPatterns {
				if strings.Contains(line, pattern) {
					findings = append(findings, buildFinding(w, path, lineNum+1, strings.TrimSpace(line)))
					break
				}
			}
		}
	}

	return scanner.AnnotateFindings(findings), nil
}

// callPatternsForWrapper generates the string patterns to search for when
// looking for calls to a custom wrapper function.
func callPatternsForWrapper(w *config.CustomWrapper) []string {
	// For dotted names like "mycompany.crypto.encrypt", generate both:
	// 1. The full qualified name with "("
	// 2. The short function name with "(" (for cases where the module is imported)
	patterns := []string{w.Name + "("}

	// Also match the short name (last segment after ".").
	if idx := strings.LastIndex(w.Name, "."); idx >= 0 {
		shortName := w.Name[idx+1:]
		if shortName != "" {
			patterns = append(patterns, shortName+"(")
		}
	}

	return patterns
}

// buildFinding creates a Finding from a matched custom wrapper call.
func buildFinding(w *config.CustomWrapper, path string, line int, snippet string) types.Finding {
	id := findingCounter.Add(1)

	assetType := types.AssetAlgorithm
	switch strings.ToLower(w.Type) {
	case "protocol":
		assetType = types.AssetProtocol
	case "certificate":
		assetType = types.AssetCertificate
	case "related-crypto-material":
		assetType = types.AssetRelatedCryptoMaterial
	}

	severity := types.SeverityInfo
	switch strings.ToLower(w.Severity) {
	case "critical":
		severity = types.SeverityCritical
	case "high":
		severity = types.SeverityHigh
	case "medium":
		severity = types.SeverityMedium
	case "low":
		severity = types.SeverityLow
	}

	return types.Finding{
		ID:        fmt.Sprintf("CUSTOM-%d", id),
		AssetType: assetType,
		Name:      w.Name,
		Location: types.Location{
			File:      path,
			StartLine: line,
			EndLine:   line,
			Snippet:   snippet,
		},
		Severity:   severity,
		Confidence: types.ConfidenceMedium,
		Properties: types.CryptoProperties{
			AlgorithmFamily: extractAlgorithmFamily(w.Name),
		},
		Description: fmt.Sprintf("Custom crypto wrapper %q called", w.Name),
		RuleID:      fmt.Sprintf("cbom-custom-%s", sanitizeRuleID(w.Name)),
		Pass:        1,
	}
}

// detectLanguageFromPath infers the programming language from a file path.
func detectLanguageFromPath(path string) string {
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(lower, ".py"), strings.HasSuffix(lower, ".pyw"):
		return "python"
	case strings.HasSuffix(lower, ".java"):
		return "java"
	case strings.HasSuffix(lower, ".kt"), strings.HasSuffix(lower, ".kts"):
		return "kotlin"
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".ts"),
		strings.HasSuffix(lower, ".jsx"), strings.HasSuffix(lower, ".tsx"):
		return "javascript"
	case strings.HasSuffix(lower, ".go"):
		return "go"
	case strings.HasSuffix(lower, ".cs"):
		return "csharp"
	case strings.HasSuffix(lower, ".rb"):
		return "ruby"
	case strings.HasSuffix(lower, ".php"):
		return "php"
	case strings.HasSuffix(lower, ".rs"):
		return "rust"
	case strings.HasSuffix(lower, ".swift"):
		return "swift"
	case strings.HasSuffix(lower, ".c"), strings.HasSuffix(lower, ".cpp"),
		strings.HasSuffix(lower, ".cc"), strings.HasSuffix(lower, ".h"),
		strings.HasSuffix(lower, ".hpp"):
		return "cpp"
	case strings.HasSuffix(lower, ".dart"):
		return "dart"
	default:
		return ""
	}
}

// extractAlgorithmFamily tries to infer a reasonable algorithm family name
// from the wrapper function name.
func extractAlgorithmFamily(name string) string {
	lower := strings.ToLower(name)

	for _, keyword := range []string{"encrypt", "decrypt", "sign", "verify", "hash", "hmac", "kdf"} {
		if strings.Contains(lower, keyword) {
			return keyword
		}
	}

	// Use the last dotted component as fallback.
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return strings.ToLower(name[idx+1:])
	}
	return strings.ToLower(name)
}

// sanitizeRuleID converts a wrapper name to a valid rule ID component.
func sanitizeRuleID(name string) string {
	var result strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		} else if r == '.' || r == '_' || r == '/' {
			result.WriteRune('-')
		}
	}
	return result.String()
}
