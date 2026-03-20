package configfile

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// OpenSSLCnfScanner detects weak cryptographic defaults in openssl.cnf files.
type OpenSSLCnfScanner struct{}

// NewOpenSSLCnf creates a new OpenSSLCnfScanner.
func NewOpenSSLCnf() *OpenSSLCnfScanner {
	return &OpenSSLCnfScanner{}
}

// Name returns the scanner name.
func (s *OpenSSLCnfScanner) Name() string { return "openssl-cnf" }

// Extensions returns the file extensions this scanner handles.
func (s *OpenSSLCnfScanner) Extensions() []string { return []string{".cnf"} }

// ScanFile scans an openssl.cnf file for weak cryptographic defaults.
func (s *OpenSSLCnfScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	var findings []types.Finding
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		lineStr := strings.TrimSpace(string(line))
		lineNum := i + 1

		// Skip comments and empty lines and section headers.
		if lineStr == "" || strings.HasPrefix(lineStr, "#") || strings.HasPrefix(lineStr, "[") {
			continue
		}

		// Parse key = value pairs.
		eqIdx := strings.Index(lineStr, "=")
		if eqIdx < 0 {
			continue
		}

		key := strings.TrimSpace(lineStr[:eqIdx])
		value := strings.TrimSpace(lineStr[eqIdx+1:])

		switch strings.ToLower(key) {
		case "default_md":
			findings = append(findings, s.scanDefaultMD(path, lineNum, lineStr, value)...)
		case "default_bits":
			findings = append(findings, s.scanDefaultBits(path, lineNum, lineStr, value)...)
		}
	}

	return findings, nil
}

// scanDefaultMD checks if the default message digest is weak.
func (s *OpenSSLCnfScanner) scanDefaultMD(path string, line int, snippet, value string) []types.Finding {
	var findings []types.Finding
	valueLower := strings.ToLower(value)

	if valueLower == "md5" {
		findings = append(findings, makeFinding(
			types.AssetAlgorithm,
			"Weak digest: MD5",
			path, line, snippet,
			types.SeverityHigh,
			"openssl.cnf default_md set to broken MD5",
			"cbom-configfile-openssl-weak-digest",
			types.CryptoProperties{AlgorithmFamily: "md5", Primitive: "hash"},
		))
	} else if valueLower == "sha1" || valueLower == "sha-1" {
		findings = append(findings, makeFinding(
			types.AssetAlgorithm,
			"Weak digest: SHA-1",
			path, line, snippet,
			types.SeverityHigh,
			"openssl.cnf default_md set to deprecated SHA-1",
			"cbom-configfile-openssl-weak-digest",
			types.CryptoProperties{AlgorithmFamily: "sha1", Primitive: "hash"},
		))
	}

	return findings
}

// scanDefaultBits checks if the default key size is too small.
func (s *OpenSSLCnfScanner) scanDefaultBits(path string, line int, snippet, value string) []types.Finding {
	var findings []types.Finding

	bits, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return nil
	}

	if bits < 2048 {
		sev := types.SeverityHigh
		if bits <= 1024 {
			sev = types.SeverityCritical
		}

		findings = append(findings, makeFinding(
			types.AssetRelatedCryptoMaterial,
			fmt.Sprintf("Weak key size: %d bits", bits),
			path, line, snippet,
			sev,
			fmt.Sprintf("openssl.cnf default_bits set to %d (minimum recommended: 2048)", bits),
			"cbom-configfile-openssl-weak-keysize",
			types.CryptoProperties{KeySize: bits},
		))
	}

	return findings
}
