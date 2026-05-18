package configfile

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

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

	return scanner.AnnotateFindings(findings), nil
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
