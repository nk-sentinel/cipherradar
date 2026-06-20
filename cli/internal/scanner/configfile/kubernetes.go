package configfile

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/certutil"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// k8sCertDataRE matches a Kubernetes Secret data entry whose key looks like a
// certificate (tls.crt, ca.crt, *.crt/.cer/.pem) with a base64 value.
var k8sCertDataRE = regexp.MustCompile(`(?m)^\s*([\w.-]+\.(?:crt|cer|pem)):\s+([A-Za-z0-9+/=]{40,})\s*$`)

// KubernetesScanner detects TLS-related configurations in Kubernetes manifests.
type KubernetesScanner struct{}

// NewKubernetes creates a new KubernetesScanner.
func NewKubernetes() *KubernetesScanner {
	return &KubernetesScanner{}
}

// Name returns the scanner name.
func (s *KubernetesScanner) Name() string { return "kubernetes" }

// Extensions returns the file extensions this scanner handles.
func (s *KubernetesScanner) Extensions() []string { return []string{".yaml", ".yml"} }

// ScanFile scans a Kubernetes manifest for TLS-related configurations.
func (s *KubernetesScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Only process files that look like Kubernetes manifests.
	if !isKubernetesManifest(content) {
		return nil, nil
	}

	var findings []types.Finding
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		lineStr := string(line)
		trimmed := strings.TrimSpace(lineStr)
		lineNum := i + 1

		// Skip comments and empty lines.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect TLS secrets (type: kubernetes.io/tls).
		if strings.Contains(trimmed, "kubernetes.io/tls") {
			findings = append(findings, makeFinding(
				types.AssetCertificate,
				"Kubernetes TLS secret",
				path, lineNum, trimmed,
				types.SeverityInfo,
				"Kubernetes TLS secret detected",
				"cbom-configfile-k8s-tls-secret",
				types.CryptoProperties{CertificateFormat: "PEM"},
			))
		}

		// Detect secretName in Ingress TLS config.
		if strings.Contains(trimmed, "secretName:") {
			secretName := strings.TrimSpace(strings.TrimPrefix(trimmed, "secretName:"))
			findings = append(findings, makeFinding(
				types.AssetCertificate,
				fmt.Sprintf("Ingress TLS secret: %s", secretName),
				path, lineNum, trimmed,
				types.SeverityInfo,
				fmt.Sprintf("Kubernetes Ingress references TLS secret %q", secretName),
				"cbom-configfile-k8s-ingress-tls",
				types.CryptoProperties{CertificateFormat: "PEM"},
			))
		}

		// Detect cipher annotations in Ingress.
		if strings.Contains(trimmed, "ssl-ciphers") {
			findings = append(findings, s.scanCipherAnnotation(path, lineNum, trimmed)...)
		}

		// Detect protocol annotations in Ingress.
		if strings.Contains(trimmed, "ssl-protocols") {
			findings = append(findings, s.scanProtocolAnnotation(path, lineNum, trimmed)...)
		}
	}

	// Decode and parse base64-encoded certificate data in Secret `data` blocks
	// (e.g. tls.crt / ca.crt), so the actual certificate is inventoried — not
	// just the secret's presence.
	findings = append(findings, scanSecretCertData(path, content)...)

	return scanner.AnnotateFindings(findings), nil
}

// scanSecretCertData finds base64-encoded certificate values in a manifest,
// decodes them (PEM or DER), and emits a full certificate finding per cert so
// they flow through the same linked-graph modeling as file certificates.
func scanSecretCertData(path string, content []byte) []types.Finding {
	var findings []types.Finding
	lineOf := byteLineIndex(content)
	for _, m := range k8sCertDataRE.FindAllSubmatchIndex(content, -1) {
		key := string(content[m[2]:m[3]])
		b64 := string(content[m[4]:m[5]])
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		line := lineOf(m[0])
		for _, cert := range parseCertsFromBytes(decoded) {
			f := certutil.BuildFinding(cert, path, line, nextID,
				"cbom-configfile-k8s-cert", "X.509",
				fmt.Sprintf("%s (k8s secret data)", key),
				fmt.Sprintf("X.509 certificate from Kubernetes secret key %q for ", key))
			findings = append(findings, f)
		}
	}
	return findings
}

// parseCertsFromBytes parses certificates from decoded secret data, which may be
// PEM-armored (possibly a chain) or raw DER.
func parseCertsFromBytes(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := data
	sawPEM := false
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				certs = append(certs, c)
			}
		}
		rest = remainder
	}
	if !sawPEM {
		if ders, err := x509.ParseCertificates(data); err == nil {
			certs = append(certs, ders...)
		}
	}
	return certs
}

// byteLineIndex returns a function mapping a byte offset to a 1-based line number.
func byteLineIndex(content []byte) func(int) int {
	return func(off int) int {
		if off > len(content) {
			off = len(content)
		}
		return bytes.Count(content[:off], []byte("\n")) + 1
	}
}

// scanCipherAnnotation checks cipher annotations for weak ciphers.
func (s *KubernetesScanner) scanCipherAnnotation(path string, line int, directive string) []types.Finding {
	var findings []types.Finding

	// Extract the value from the annotation.
	parts := strings.SplitN(directive, ":", 2)
	if len(parts) < 2 {
		return nil
	}
	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, "\"'")

	ciphers := strings.Split(value, ":")
	for _, cipher := range ciphers {
		cipher = strings.TrimSpace(cipher)
		if strings.HasPrefix(cipher, "!") {
			continue
		}
		if weakCiphers[cipher] {
			findings = append(findings, makeFinding(
				types.AssetAlgorithm,
				fmt.Sprintf("Weak cipher in K8s annotation: %s", cipher),
				path, line, directive,
				types.SeverityHigh,
				fmt.Sprintf("Kubernetes Ingress ssl-ciphers annotation includes weak cipher %s", cipher),
				"cbom-configfile-k8s-weak-cipher",
				types.CryptoProperties{CipherSuites: []string{cipher}},
			))
		}
	}

	return findings
}

// scanProtocolAnnotation checks protocol annotations for weak protocols.
func (s *KubernetesScanner) scanProtocolAnnotation(path string, line int, directive string) []types.Finding {
	var findings []types.Finding

	parts := strings.SplitN(directive, ":", 2)
	if len(parts) < 2 {
		return nil
	}
	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, "\"'")

	protocols := strings.Fields(value)
	for _, proto := range protocols {
		protoLower := strings.ToLower(proto)
		if protoLower == "tlsv1" || protoLower == "tlsv1.0" || protoLower == "tlsv1.1" {
			findings = append(findings, makeFinding(
				types.AssetProtocol,
				fmt.Sprintf("Weak TLS protocol in K8s annotation: %s", proto),
				path, line, directive,
				types.SeverityHigh,
				fmt.Sprintf("Kubernetes Ingress ssl-protocols annotation includes deprecated %s", proto),
				"cbom-configfile-k8s-weak-protocol",
				types.CryptoProperties{ProtocolType: "tls", ProtocolVersion: proto},
			))
		}
	}

	return findings
}

// isKubernetesManifest heuristically determines if the content is a Kubernetes manifest.
func isKubernetesManifest(content []byte) bool {
	markers := [][]byte{
		[]byte("apiVersion:"),
		[]byte("kind:"),
	}
	matchCount := 0
	for _, m := range markers {
		if bytes.Contains(content, m) {
			matchCount++
		}
	}
	// Require both apiVersion and kind to identify a K8s manifest.
	return matchCount >= 2
}
