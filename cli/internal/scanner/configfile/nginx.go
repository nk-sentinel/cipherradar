package configfile

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// NginxScanner detects TLS/SSL configuration issues in nginx.conf files.
type NginxScanner struct{}

// NewNginx creates a new NginxScanner.
func NewNginx() *NginxScanner {
	return &NginxScanner{}
}

// Name returns the scanner name.
func (s *NginxScanner) Name() string { return "nginx" }

// Extensions returns the file extensions this scanner handles.
func (s *NginxScanner) Extensions() []string { return []string{".conf"} }

// ScanFile scans an nginx configuration file for crypto-related settings.
func (s *NginxScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Only process files that look like nginx config (contain nginx-specific directives).
	if !isNginxConfig(content) {
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

		// Detect ssl_protocols directive.
		if strings.HasPrefix(lineStr, "ssl_protocols") {
			findings = append(findings, s.scanSSLProtocols(path, lineNum, lineStr)...)
		}

		// Detect ssl_ciphers directive.
		if strings.HasPrefix(lineStr, "ssl_ciphers") {
			findings = append(findings, s.scanSSLCiphers(path, lineNum, lineStr)...)
		}

		// Detect ssl_certificate and ssl_certificate_key paths.
		if strings.HasPrefix(lineStr, "ssl_certificate_key") {
			findings = append(findings, s.scanCertKeyPath(path, lineNum, lineStr))
		} else if strings.HasPrefix(lineStr, "ssl_certificate") {
			findings = append(findings, s.scanCertPath(path, lineNum, lineStr))
		}
	}

	return scanner.AnnotateFindings(findings), nil
}

// scanSSLProtocols checks for weak TLS/SSL protocols.
func (s *NginxScanner) scanSSLProtocols(path string, line int, directive string) []types.Finding {
	var findings []types.Finding
	value := extractDirectiveValue(directive, "ssl_protocols")

	protocols := strings.Fields(value)
	for _, proto := range protocols {
		proto = strings.TrimSuffix(proto, ";")
		protoLower := strings.ToLower(proto)

		if protoLower == "tlsv1" || protoLower == "tlsv1.0" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				fmt.Sprintf("Weak TLS protocol: %s", proto),
				path, line, strings.TrimSpace(directive),
				types.SeverityHigh,
				fmt.Sprintf("nginx ssl_protocols includes deprecated %s", proto),
				"cbom-configfile-nginx-weak-protocol",
				types.CryptoProperties{ProtocolType: "tls", ProtocolVersion: proto},
			))
		} else if protoLower == "tlsv1.1" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				fmt.Sprintf("Weak TLS protocol: %s", proto),
				path, line, strings.TrimSpace(directive),
				types.SeverityHigh,
				fmt.Sprintf("nginx ssl_protocols includes deprecated %s", proto),
				"cbom-configfile-nginx-weak-protocol",
				types.CryptoProperties{ProtocolType: "tls", ProtocolVersion: proto},
			))
		} else if protoLower == "sslv3" || protoLower == "sslv2" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				fmt.Sprintf("Insecure protocol: %s", proto),
				path, line, strings.TrimSpace(directive),
				types.SeverityCritical,
				fmt.Sprintf("nginx ssl_protocols includes broken %s", proto),
				"cbom-configfile-nginx-weak-protocol",
				types.CryptoProperties{ProtocolType: "ssl", ProtocolVersion: proto},
			))
		}
	}

	return findings
}

// scanSSLCiphers checks for weak cipher suites.
func (s *NginxScanner) scanSSLCiphers(path string, line int, directive string) []types.Finding {
	var findings []types.Finding
	value := extractDirectiveValue(directive, "ssl_ciphers")
	value = strings.TrimSuffix(strings.TrimSpace(value), ";")
	value = strings.Trim(value, "\"'")

	ciphers := strings.Split(value, ":")
	for _, cipher := range ciphers {
		cipher = strings.TrimSpace(cipher)
		// Skip negation prefixes.
		if strings.HasPrefix(cipher, "!") {
			continue
		}
		if weakCiphers[cipher] {
			findings = append(findings, makeFinding(
				types.AssetAlgorithm,
				fmt.Sprintf("Weak cipher: %s", cipher),
				path, line, strings.TrimSpace(directive),
				types.SeverityHigh,
				fmt.Sprintf("nginx ssl_ciphers includes weak cipher %s", cipher),
				"cbom-configfile-nginx-weak-cipher",
				types.CryptoProperties{CipherSuites: []string{cipher}},
			))
		}
	}

	return findings
}

// scanCertPath extracts the ssl_certificate path.
func (s *NginxScanner) scanCertPath(path string, line int, directive string) types.Finding {
	value := extractDirectiveValue(directive, "ssl_certificate")
	value = strings.TrimSuffix(strings.TrimSpace(value), ";")

	return makeFinding(
		types.AssetCertificate,
		fmt.Sprintf("TLS certificate: %s", value),
		path, line, strings.TrimSpace(directive),
		types.SeverityInfo,
		fmt.Sprintf("nginx TLS certificate configured at %s", value),
		"cbom-configfile-nginx-certificate",
		types.CryptoProperties{CertificateFormat: "PEM"},
	)
}

// scanCertKeyPath extracts the ssl_certificate_key path.
func (s *NginxScanner) scanCertKeyPath(path string, line int, directive string) types.Finding {
	value := extractDirectiveValue(directive, "ssl_certificate_key")
	value = strings.TrimSuffix(strings.TrimSpace(value), ";")

	return makeFinding(
		types.AssetRelatedCryptoMaterial,
		fmt.Sprintf("TLS private key: %s", value),
		path, line, strings.TrimSpace(directive),
		types.SeverityInfo,
		fmt.Sprintf("nginx TLS private key configured at %s", value),
		"cbom-configfile-nginx-private-key",
		types.CryptoProperties{MaterialType: "private-key"},
	)
}

// isNginxConfig heuristically determines if the content is an nginx config.
func isNginxConfig(content []byte) bool {
	// Check for nginx-specific directives.
	markers := [][]byte{
		[]byte("server {"),
		[]byte("server{"),
		[]byte("ssl_protocols"),
		[]byte("ssl_ciphers"),
		[]byte("ssl_certificate"),
		[]byte("proxy_pass"),
		[]byte("location"),
		[]byte("upstream"),
		[]byte("nginx"),
	}
	for _, m := range markers {
		if bytes.Contains(content, m) {
			return true
		}
	}
	return false
}

// extractDirectiveValue extracts the value part from an nginx directive line.
func extractDirectiveValue(line, directive string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, directive) {
		return ""
	}
	value := strings.TrimPrefix(trimmed, directive)
	return strings.TrimSpace(value)
}
