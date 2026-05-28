package configfile

import (
	"bytes"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
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
		case "ssl.KeyManagerFactory.algorithm", "ssl.TrustManagerFactory.algorithm":
			if f, ok := s.scanKeyManagerAlgorithm(path, lineNum, lineStr, key, value); ok {
				findings = append(findings, f)
			}
		case "keystore.type":
			if f, ok := s.scanKeystoreType(path, lineNum, lineStr, value); ok {
				findings = append(findings, f)
			}
		}
	}

	return scanner.AnnotateFindings(findings), nil
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

// keyManagerAlgorithms maps known JSSE KeyManager/TrustManager factory
// algorithm names (case-insensitive) to a canonical display name. These name
// the certificate/key-management algorithm the JVM uses for X.509 handling and
// are inventory assets. The map gates emission so unknown/garbage values don't
// produce spurious findings (strict zero-FP rule).
var keyManagerAlgorithms = map[string]string{
	"sunx509":    "SunX509",
	"pkix":       "PKIX",
	"x509":       "X509",
	"newsunx509": "NewSunX509",
	"ibmx509":    "IbmX509",
}

// scanKeyManagerAlgorithm emits an inventory asset for the JSSE
// KeyManagerFactory/TrustManagerFactory algorithm (e.g. SunX509, PKIX). The
// value is validated against a known-algorithm set so only real algorithm
// names are reported.
func (s *JavaSecurityScanner) scanKeyManagerAlgorithm(path string, line int, snippet, key, value string) (types.Finding, bool) {
	canonical, ok := keyManagerAlgorithms[strings.ToLower(strings.TrimSpace(value))]
	if !ok {
		return types.Finding{}, false
	}

	factory := "KeyManagerFactory"
	if strings.Contains(key, "TrustManagerFactory") {
		factory = "TrustManagerFactory"
	}

	return makeFinding(
		types.AssetAlgorithm,
		canonical,
		path, line, truncateSnippet(snippet),
		types.SeverityInfo,
		"java.security configures JSSE "+factory+" algorithm "+canonical,
		"cbom-configfile-java-keymanager-algorithm",
		types.CryptoProperties{AlgorithmFamily: strings.ToLower(canonical)},
	), true
}

// keystoreTypes maps known Java keystore types (case-insensitive) to a
// canonical display name. Gating on this set keeps emission tight.
var keystoreTypes = map[string]string{
	"pkcs12": "PKCS12",
	"jks":    "JKS",
	"jceks":  "JCEKS",
	"bks":    "BKS",
	"dks":    "DKS",
}

// scanKeystoreType emits a related-crypto-material asset for the configured
// keystore type (e.g. PKCS12). Only recognized keystore types are reported.
func (s *JavaSecurityScanner) scanKeystoreType(path string, line int, snippet, value string) (types.Finding, bool) {
	canonical, ok := keystoreTypes[strings.ToLower(strings.TrimSpace(value))]
	if !ok {
		return types.Finding{}, false
	}

	return makeFinding(
		types.AssetRelatedCryptoMaterial,
		canonical,
		path, line, truncateSnippet(snippet),
		types.SeverityInfo,
		"java.security configures keystore type "+canonical,
		"cbom-configfile-java-keystore-type",
		types.CryptoProperties{MaterialType: "key-store"},
	), true
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
