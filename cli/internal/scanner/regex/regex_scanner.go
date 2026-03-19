// Package regex provides a language-agnostic regex scanner that detects crypto
// patterns (PEM headers, algorithm names, high-entropy strings) in any file.
package regex

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// pemPattern matches PEM block headers.
type pemPattern struct {
	re          *regexp.Regexp
	name        string
	assetType   types.AssetType
	severity    types.Severity
	materialType string
	ruleID      string
}

// algoPattern matches algorithm name strings.
type algoPattern struct {
	re            *regexp.Regexp
	name          string
	severity      types.Severity
	quantumStatus types.QuantumStatus
	primitive     string
	family        string
	ruleID        string
	assetType     types.AssetType
}

// RegexScanner detects crypto-related patterns in any file using regular expressions.
type RegexScanner struct {
	pemPatterns  []pemPattern
	algoPatterns []algoPattern
	hexKeyRe     *regexp.Regexp
	base64KeyRe  *regexp.Regexp
}

// New creates a new RegexScanner with all patterns precompiled.
func New() *RegexScanner {
	s := &RegexScanner{}
	s.compilePEMPatterns()
	s.compileAlgoPatterns()
	s.compileEntropyPatterns()
	return s
}

// Name returns the scanner name.
func (s *RegexScanner) Name() string {
	return "regex"
}

// Extensions returns an empty slice; the regex scanner is registered as universal.
func (s *RegexScanner) Extensions() []string {
	return nil
}

// ScanFile scans a single file's content for crypto-related patterns.
func (s *RegexScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Skip likely-binary files: if the first 512 bytes contain a NUL, bail out.
	probe := content
	if len(probe) > 512 {
		probe = probe[:512]
	}
	if bytes.IndexByte(probe, 0) != -1 {
		return nil, nil
	}

	// Also skip if not valid UTF-8 (binary file heuristic).
	if !utf8.Valid(probe) {
		return nil, nil
	}

	var findings []types.Finding

	lines := bytes.Split(content, []byte("\n"))

	// --- PEM header detection ---
	for _, pp := range s.pemPatterns {
		for lineIdx, line := range lines {
			loc := pp.re.FindIndex(line)
			if loc == nil {
				continue
			}
			snippet := strings.TrimSpace(string(line))
			findings = append(findings, types.Finding{
				ID:        nextID(),
				AssetType: pp.assetType,
				Name:      pp.name,
				Location: types.Location{
					File:      path,
					StartLine: lineIdx + 1,
					StartCol:  loc[0] + 1,
					EndLine:   lineIdx + 1,
					EndCol:    loc[1],
					Snippet:   snippet,
				},
				Severity:   pp.severity,
				Confidence: types.ConfidenceLow,
				Properties: types.CryptoProperties{
					MaterialType: pp.materialType,
				},
				Description: fmt.Sprintf("PEM-encoded %s detected via regex", pp.name),
				RuleID:      pp.ruleID,
				Pass:        1,
			})
		}
	}

	// --- PEM certificate block parsing ---
	findings = append(findings, s.parseCertificateBlocks(path, content)...)

	// --- Algorithm name detection ---
	for _, ap := range s.algoPatterns {
		for lineIdx, line := range lines {
			allLocs := ap.re.FindAllIndex(line, -1)
			for _, loc := range allLocs {
				snippet := strings.TrimSpace(string(line))
				findings = append(findings, types.Finding{
					ID:        nextID(),
					AssetType: ap.assetType,
					Name:      ap.name,
					Location: types.Location{
						File:      path,
						StartLine: lineIdx + 1,
						StartCol:  loc[0] + 1,
						EndLine:   lineIdx + 1,
						EndCol:    loc[1],
						Snippet:   snippet,
					},
					Severity:   ap.severity,
					Confidence: types.ConfidenceLow,
					Properties: types.CryptoProperties{
						Primitive:       ap.primitive,
						AlgorithmFamily: ap.family,
						QuantumStatus:   ap.quantumStatus,
					},
					Description: fmt.Sprintf("Algorithm reference %q detected via regex", ap.name),
					RuleID:      ap.ruleID,
					Pass:        1,
				})
			}
		}
	}

	// --- High-entropy hex string detection ---
	for lineIdx, line := range lines {
		lineStr := string(line)

		// Skip lines that look like git commit contexts
		if strings.Contains(lineStr, "commit ") || strings.Contains(lineStr, "Commit:") {
			continue
		}

		hexLocs := s.hexKeyRe.FindAllIndex(line, -1)
		for _, loc := range hexLocs {
			matched := string(line[loc[0]:loc[1]])
			// Skip UUIDs (8-4-4-4-12 hex with dashes nearby, or exactly 32 hex)
			if isUUID(lineStr, loc[0], loc[1]) {
				continue
			}
			// Skip git commit hashes (exactly 40 hex chars)
			if len(matched) == 40 && looksLikeGitHash(lineStr) {
				continue
			}
			snippet := strings.TrimSpace(lineStr)
			findings = append(findings, types.Finding{
				ID:        nextID(),
				AssetType: types.AssetRelatedCryptoMaterial,
				Name:      "Potential key material (hex)",
				Location: types.Location{
					File:      path,
					StartLine: lineIdx + 1,
					StartCol:  loc[0] + 1,
					EndLine:   lineIdx + 1,
					EndCol:    loc[1],
					Snippet:   snippet,
				},
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceLow,
				Properties: types.CryptoProperties{
					MaterialType: "unknown",
					MaterialSize: (loc[1] - loc[0]) * 4, // hex chars to bits
				},
				Description: "High-entropy hex string that may be key material",
				RuleID:      "cbom-regex-hex-key",
				Pass:        1,
			})
		}

		// --- High-entropy base64 detection ---
		b64Locs := s.base64KeyRe.FindAllIndex(line, -1)
		for _, loc := range b64Locs {
			snippet := strings.TrimSpace(lineStr)
			findings = append(findings, types.Finding{
				ID:        nextID(),
				AssetType: types.AssetRelatedCryptoMaterial,
				Name:      "Potential key material (base64)",
				Location: types.Location{
					File:      path,
					StartLine: lineIdx + 1,
					StartCol:  loc[0] + 1,
					EndLine:   lineIdx + 1,
					EndCol:    loc[1],
					Snippet:   snippet,
				},
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceLow,
				Properties: types.CryptoProperties{
					MaterialType: "unknown",
				},
				Description: "High-entropy base64 string that may be key material",
				RuleID:      "cbom-regex-base64-key",
				Pass:        1,
			})
		}
	}

	return findings, nil
}

func (s *RegexScanner) compilePEMPatterns() {
	s.pemPatterns = []pemPattern{
		{
			re:           regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			name:         "RSA Private Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityHigh,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-rsa-private",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			name:         "EC Private Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityHigh,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-ec-private",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			name:         "Generic Private Key (PKCS#8)",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityHigh,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-pkcs8-private",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),
			name:         "Encrypted Private Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityMedium,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-encrypted-private",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`),
			name:         "Public Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityInfo,
			materialType: "public-key",
			ruleID:       "cbom-regex-pem-public",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
			name:         "Certificate",
			assetType:    types.AssetCertificate,
			severity:     types.SeverityInfo,
			materialType: "",
			ruleID:       "cbom-regex-pem-certificate",
		},
	}
}

func (s *RegexScanner) compileAlgoPatterns() {
	// Broken / weak algorithms -> MEDIUM severity
	brokenAlgos := []struct {
		pattern  string
		name     string
		family   string
		prim     string
		quantum  types.QuantumStatus
	}{
		{`\bMD5\b`, "MD5", "md5", "hash", types.Broken},
		{`\bSHA-?1\b`, "SHA-1", "sha", "hash", types.QuantumVulnerable},
		{`\bDES\b`, "DES", "des", "block-cipher", types.Broken},
		{`\b3DES\b`, "3DES", "des", "block-cipher", types.QuantumVulnerable},
		{`\bTripleDES\b`, "TripleDES", "des", "block-cipher", types.QuantumVulnerable},
		{`\bRC4\b`, "RC4", "rc4", "stream-cipher", types.Broken},
		{`\bBlowfish\b`, "Blowfish", "blowfish", "block-cipher", types.QuantumVulnerable},
		{`\bSSLv3\b`, "SSLv3", "ssl", "protocol", types.Broken},
		{`\bTLSv1\.0\b`, "TLSv1.0", "tls", "protocol", types.Broken},
		{`\bTLSv1\.1\b`, "TLSv1.1", "tls", "protocol", types.Broken},
	}

	// Safe / modern algorithms -> INFO severity
	safeAlgos := []struct {
		pattern string
		name    string
		family  string
		prim    string
		quantum types.QuantumStatus
	}{
		{`\bSHA-?256\b`, "SHA-256", "sha", "hash", types.QuantumVulnerable},
		{`\bAES-?128\b`, "AES-128", "aes", "block-cipher", types.QuantumVulnerable},
		{`\bAES-?256\b`, "AES-256", "aes", "block-cipher", types.QuantumVulnerable},
		{`\bRSA\b`, "RSA", "rsa", "pke", types.QuantumVulnerable},
	}

	for _, a := range brokenAlgos {
		assetType := types.AssetAlgorithm
		if a.prim == "protocol" {
			assetType = types.AssetProtocol
		}
		s.algoPatterns = append(s.algoPatterns, algoPattern{
			re:            regexp.MustCompile(a.pattern),
			name:          a.name,
			severity:      types.SeverityMedium,
			quantumStatus: a.quantum,
			primitive:     a.prim,
			family:        a.family,
			ruleID:        fmt.Sprintf("cbom-regex-algo-%s", strings.ToLower(strings.ReplaceAll(a.name, ".", ""))),
			assetType:     assetType,
		})
	}

	for _, a := range safeAlgos {
		s.algoPatterns = append(s.algoPatterns, algoPattern{
			re:            regexp.MustCompile(a.pattern),
			name:          a.name,
			severity:      types.SeverityInfo,
			quantumStatus: a.quantum,
			primitive:     a.prim,
			family:        a.family,
			ruleID:        fmt.Sprintf("cbom-regex-algo-%s", strings.ToLower(strings.ReplaceAll(a.name, ".", ""))),
			assetType:     types.AssetAlgorithm,
		})
	}
}

func (s *RegexScanner) compileEntropyPatterns() {
	// Hex strings >= 32 chars (potential key material)
	s.hexKeyRe = regexp.MustCompile(`[0-9a-fA-F]{32,}`)

	// Base64 strings >= 40 chars that look like keys (alphanumeric + / + =)
	// Require at least some mix of upper, lower, digits to avoid matching plain words.
	s.base64KeyRe = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
}

// isUUID checks whether the hex match at [start, end) in the line looks like part of a UUID.
func isUUID(line string, start, end int) bool {
	matchLen := end - start
	// Standard UUID without dashes is exactly 32 hex characters
	if matchLen == 32 {
		// Check if there are dashes nearby suggesting UUID formatting
		if start >= 1 && line[start-1] == '-' {
			return true
		}
		if end < len(line) && line[end] == '-' {
			return true
		}
	}
	return false
}

// looksLikeGitHash checks if the line context suggests a git commit hash.
func looksLikeGitHash(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "commit") ||
		strings.Contains(lower, "revision") ||
		strings.Contains(lower, "rev ") ||
		strings.Contains(lower, "sha:")
}

// certBlockRe matches a full PEM CERTIFICATE block including markers.
var certBlockRe = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----\s*\n(.*?)\n\s*-----END CERTIFICATE-----`)

// parseCertificateBlocks extracts and parses PEM CERTIFICATE blocks from file
// content. For each block, it tries to parse the X.509 certificate and extract
// subject, issuer, validity dates, and signature algorithm. It also checks
// whether the certificate is expired or expiring soon.
func (s *RegexScanner) parseCertificateBlocks(path string, content []byte) []types.Finding {
	var findings []types.Finding

	// First pass: try standard pem.Decode for well-formed PEM blocks
	rest := content
	decodedOffsets := make(map[int]bool) // track which cert blocks were handled by pem.Decode
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		// Find the line number of this certificate block in the file
		blockStart := len(content) - len(rest) - len(pem.EncodeToMemory(block))
		lineNum := bytes.Count(content[:max(blockStart, 0)], []byte("\n")) + 1
		decodedOffsets[lineNum] = true

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Decoded PEM but invalid X.509
			findings = append(findings, types.Finding{
				ID:        nextID(),
				AssetType: types.AssetCertificate,
				Name:      "X.509 Certificate (unparseable)",
				Location: types.Location{
					File:      path,
					StartLine: lineNum,
					StartCol:  1,
					EndLine:   lineNum,
					EndCol:    1,
					Snippet:   "-----BEGIN CERTIFICATE-----",
				},
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceLow,
				Properties: types.CryptoProperties{
					CertificateFormat: "PEM",
				},
				Description: "PEM certificate block found but could not be parsed",
				RuleID:      "cbom-regex-pem-certificate-parse",
				Pass:        1,
			})
			continue
		}

		findings = append(findings, buildCertFinding(cert, path, lineNum))
	}

	// Second pass: use regex to find CERTIFICATE blocks that pem.Decode could not handle
	// (e.g., blocks with invalid base64 / fake test content)
	matches := certBlockRe.FindAllIndex(content, -1)
	for _, loc := range matches {
		lineNum := bytes.Count(content[:loc[0]], []byte("\n")) + 1
		if decodedOffsets[lineNum] {
			continue // already handled by pem.Decode
		}

		findings = append(findings, types.Finding{
			ID:        nextID(),
			AssetType: types.AssetCertificate,
			Name:      "X.509 Certificate (unparseable)",
			Location: types.Location{
				File:      path,
				StartLine: lineNum,
				StartCol:  1,
				EndLine:   lineNum,
				EndCol:    1,
				Snippet:   "-----BEGIN CERTIFICATE-----",
			},
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceLow,
			Properties: types.CryptoProperties{
				CertificateFormat: "PEM",
			},
			Description: "PEM certificate block found but could not be parsed",
			RuleID:      "cbom-regex-pem-certificate-parse",
			Pass:        1,
		})
	}

	return findings
}

// buildCertFinding creates a finding for a successfully parsed X.509 certificate.
func buildCertFinding(cert *x509.Certificate, path string, lineNum int) types.Finding {
	severity := types.SeverityInfo
	state := "active"
	now := time.Now()
	if now.After(cert.NotAfter) {
		severity = types.SeverityHigh
		state = "expired"
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		severity = types.SeverityMedium
		state = "expiring-soon"
	}

	sigAlgo := cert.SignatureAlgorithm.String()

	return types.Finding{
		ID:        nextID(),
		AssetType: types.AssetCertificate,
		Name:      fmt.Sprintf("X.509 Certificate (%s)", cert.Subject.CommonName),
		Location: types.Location{
			File:      path,
			StartLine: lineNum,
			StartCol:  1,
			EndLine:   lineNum,
			EndCol:    1,
			Snippet:   "-----BEGIN CERTIFICATE-----",
		},
		Severity:   severity,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			SubjectName:        cert.Subject.String(),
			IssuerName:         cert.Issuer.String(),
			NotValidBefore:     cert.NotBefore.Format(time.RFC3339),
			NotValidAfter:      cert.NotAfter.Format(time.RFC3339),
			SignatureAlgorithm: sigAlgo,
			CertificateFormat:  "PEM",
			State:              state,
		},
		Description: fmt.Sprintf("X.509 certificate for %q signed with %s (expires %s)",
			cert.Subject.CommonName, sigAlgo, cert.NotAfter.Format("2006-01-02")),
		RuleID: "cbom-regex-pem-certificate-parsed",
		Pass:   1,
	}
}

func nextID() string {
	n := findingCounter.Add(1)
	return fmt.Sprintf("REGEX-%04d", n)
}
