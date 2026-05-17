package configfile

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// HttpdScanner detects TLS/SSL configuration issues in Apache httpd.conf files.
type HttpdScanner struct{}

// NewHttpd creates a new HttpdScanner.
func NewHttpd() *HttpdScanner {
	return &HttpdScanner{}
}

// Name returns the scanner name.
func (s *HttpdScanner) Name() string { return "httpd" }

// Extensions returns the file extensions this scanner handles.
// Note: httpd.conf shares .conf with nginx; the scanner uses heuristics
// to distinguish between them. Both are registered in defaults.go under .conf
// via a multiplexing wrapper.
func (s *HttpdScanner) Extensions() []string { return []string{".conf"} }

// ScanFile scans an Apache httpd configuration file for crypto-related settings.
func (s *HttpdScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Only process files that look like Apache httpd config.
	if !isHttpdConfig(content) {
		return nil, nil
	}

	var findings []types.Finding
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		lineStr := strings.TrimSpace(string(line))
		lineNum := i + 1

		// Skip comments and empty lines.
		if lineStr == "" || strings.HasPrefix(lineStr, "#") {
			continue
		}

		// Detect SSLProtocol directive.
		if strings.HasPrefix(lineStr, "SSLProtocol") {
			findings = append(findings, s.scanSSLProtocol(path, lineNum, lineStr)...)
		}

		// Detect SSLCipherSuite directive.
		if strings.HasPrefix(lineStr, "SSLCipherSuite") {
			findings = append(findings, s.scanSSLCipherSuite(path, lineNum, lineStr)...)
		}
	}

	return scanner.AnnotateFindings(findings), nil
}

// scanSSLProtocol checks for weak protocols in the SSLProtocol directive.
func (s *HttpdScanner) scanSSLProtocol(path string, line int, directive string) []types.Finding {
	var findings []types.Finding
	value := strings.TrimSpace(strings.TrimPrefix(directive, "SSLProtocol"))

	tokens := strings.Fields(value)
	for _, token := range tokens {
		tokenLower := strings.ToLower(token)

		// +SSLv3 or just SSLv3 (explicitly enabling)
		if tokenLower == "+sslv3" || tokenLower == "sslv3" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				"Insecure protocol: SSLv3",
				path, line, strings.TrimSpace(directive),
				types.SeverityCritical,
				"Apache SSLProtocol enables broken SSLv3",
				"cbom-configfile-httpd-weak-protocol",
				types.CryptoProperties{ProtocolType: "ssl", ProtocolVersion: "SSLv3"},
			))
		}

		if tokenLower == "+sslv2" || tokenLower == "sslv2" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				"Insecure protocol: SSLv2",
				path, line, strings.TrimSpace(directive),
				types.SeverityCritical,
				"Apache SSLProtocol enables broken SSLv2",
				"cbom-configfile-httpd-weak-protocol",
				types.CryptoProperties{ProtocolType: "ssl", ProtocolVersion: "SSLv2"},
			))
		}

		if tokenLower == "+tlsv1" || (tokenLower == "tlsv1" && !strings.Contains(tokenLower, ".")) {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				"Weak TLS protocol: TLSv1",
				path, line, strings.TrimSpace(directive),
				types.SeverityHigh,
				"Apache SSLProtocol enables deprecated TLSv1",
				"cbom-configfile-httpd-weak-protocol",
				types.CryptoProperties{ProtocolType: "tls", ProtocolVersion: "TLSv1"},
			))
		}

		if tokenLower == "+tlsv1.1" || tokenLower == "tlsv1.1" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				"Weak TLS protocol: TLSv1.1",
				path, line, strings.TrimSpace(directive),
				types.SeverityHigh,
				"Apache SSLProtocol enables deprecated TLSv1.1",
				"cbom-configfile-httpd-weak-protocol",
				types.CryptoProperties{ProtocolType: "tls", ProtocolVersion: "TLSv1.1"},
			))
		}
	}

	return findings
}

// scanSSLCipherSuite checks for weak ciphers in the SSLCipherSuite directive.
func (s *HttpdScanner) scanSSLCipherSuite(path string, line int, directive string) []types.Finding {
	var findings []types.Finding
	value := strings.TrimSpace(strings.TrimPrefix(directive, "SSLCipherSuite"))

	ciphers := strings.Split(value, ":")
	for _, cipher := range ciphers {
		cipher = strings.TrimSpace(cipher)
		if strings.HasPrefix(cipher, "!") {
			continue
		}
		if weakCiphers[cipher] {
			findings = append(findings, makeFinding(
				types.AssetAlgorithm,
				fmt.Sprintf("Weak cipher: %s", cipher),
				path, line, strings.TrimSpace(directive),
				types.SeverityHigh,
				fmt.Sprintf("Apache SSLCipherSuite includes weak cipher %s", cipher),
				"cbom-configfile-httpd-weak-cipher",
				types.CryptoProperties{CipherSuites: []string{cipher}},
			))
		}
	}

	return findings
}

// isHttpdConfig heuristically determines if the content is an Apache httpd config.
func isHttpdConfig(content []byte) bool {
	markers := [][]byte{
		[]byte("SSLProtocol"),
		[]byte("SSLCipherSuite"),
		[]byte("SSLEngine"),
		[]byte("SSLCertificateFile"),
		[]byte("<VirtualHost"),
		[]byte("ServerRoot"),
		[]byte("LoadModule"),
		[]byte("ServerName"),
	}
	for _, m := range markers {
		if bytes.Contains(content, m) {
			return true
		}
	}
	return false
}
