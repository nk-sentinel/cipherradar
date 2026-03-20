package configfile

import (
	"bytes"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// weakAlgorithms is the set of algorithms that should be disabled in Java security.
var weakAlgorithms = map[string]bool{
	"md5":     true,
	"md2":     true,
	"sha1":    true,
	"rc4":     true,
	"des":     true,
	"3des":    true,
	"sslv3":   true,
	"sslv2":   true,
	"tlsv1":   true,
	"tlsv1.1": true,
}

// JavaSecurityScanner detects weak algorithm configurations in java.security files.
type JavaSecurityScanner struct{}

// NewJavaSecurity creates a new JavaSecurityScanner.
func NewJavaSecurity() *JavaSecurityScanner {
	return &JavaSecurityScanner{}
}

// Name returns the scanner name.
func (s *JavaSecurityScanner) Name() string { return "java-security" }

// Extensions returns the file extensions this scanner handles.
func (s *JavaSecurityScanner) Extensions() []string { return []string{".security"} }

// ScanFile scans a java.security file for weak algorithm configurations.
func (s *JavaSecurityScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	var findings []types.Finding

	// Java properties can span multiple lines with backslash continuation.
	// First, join continuation lines.
	joined := joinContinuationLines(content)
	lines := bytes.Split(joined, []byte("\n"))

	for i, line := range lines {
		lineStr := strings.TrimSpace(string(line))
		lineNum := i + 1

		// Skip comments and empty lines.
		if lineStr == "" || strings.HasPrefix(lineStr, "#") || strings.HasPrefix(lineStr, "!") {
			continue
		}

		eqIdx := strings.Index(lineStr, "=")
		if eqIdx < 0 {
			continue
		}

		key := strings.TrimSpace(lineStr[:eqIdx])
		value := strings.TrimSpace(lineStr[eqIdx+1:])

		switch key {
		case "jdk.tls.disabledAlgorithms":
			findings = append(findings, s.scanDisabledAlgorithms(path, lineNum, lineStr, value, "TLS")...)
		case "jdk.certpath.disabledAlgorithms":
			findings = append(findings, s.scanDisabledAlgorithms(path, lineNum, lineStr, value, "certpath")...)
		}
	}

	return findings, nil
}

// scanDisabledAlgorithms verifies that weak algorithms are in the disabled list.
// If a known-weak algorithm is NOT present in the disabled list, it means it
// could be used, which is a security concern.
func (s *JavaSecurityScanner) scanDisabledAlgorithms(path string, line int, snippet, value, context string) []types.Finding {
	var findings []types.Finding

	// Normalize the disabled algorithm list.
	valueLower := strings.ToLower(value)

	// Check that critical weak algorithms are disabled.
	criticalAlgos := []struct {
		name     string
		pattern  string
		severity types.Severity
	}{
		{"MD5", "md5", types.SeverityHigh},
		{"RC4", "rc4", types.SeverityHigh},
		{"DES", "des", types.SeverityHigh},
		{"3DES", "3des", types.SeverityMedium},
		{"SSLv3", "sslv3", types.SeverityCritical},
	}

	if context == "TLS" {
		criticalAlgos = append(criticalAlgos,
			struct {
				name     string
				pattern  string
				severity types.Severity
			}{"TLSv1", "tlsv1", types.SeverityHigh},
			struct {
				name     string
				pattern  string
				severity types.Severity
			}{"TLSv1.1", "tlsv1.1", types.SeverityHigh},
		)
	}

	for _, algo := range criticalAlgos {
		if !strings.Contains(valueLower, algo.pattern) {
			findings = append(findings, makeFinding(
				types.AssetAlgorithm,
				"Missing disabled algorithm: "+algo.name,
				path, line, truncateSnippet(snippet),
				algo.severity,
				"java.security jdk."+strings.ToLower(context)+".disabledAlgorithms does not disable "+algo.name,
				"cbom-configfile-java-missing-disabled-algo",
				types.CryptoProperties{AlgorithmFamily: strings.ToLower(algo.name)},
			))
		}
	}

	return findings
}

// joinContinuationLines joins lines ending with backslash for Java property files.
func joinContinuationLines(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	var result [][]byte
	var current []byte

	for _, line := range lines {
		trimmed := bytes.TrimRight(line, " \t")
		if bytes.HasSuffix(trimmed, []byte("\\")) {
			// Continuation: remove the backslash and append.
			current = append(current, bytes.TrimSuffix(trimmed, []byte("\\"))...)
		} else {
			current = append(current, line...)
			result = append(result, current)
			current = nil
		}
	}
	if current != nil {
		result = append(result, current)
	}

	return bytes.Join(result, []byte("\n"))
}

// truncateSnippet truncates a snippet for display in findings.
func truncateSnippet(s string) string {
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}
