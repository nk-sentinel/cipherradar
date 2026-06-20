// Package regex provides a language-agnostic regex scanner that detects crypto
// patterns (PEM headers, algorithm names, high-entropy strings) in any file.
package regex

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// pemPattern matches PEM block headers.
type pemPattern struct {
	re           *regexp.Regexp
	name         string
	assetType    types.AssetType
	severity     types.Severity
	materialType string
	ruleID       string
	category     types.Category
	// primitive is the canonical token (phase 3a vocabulary) emitted as
	// cryptoProperties.algorithmProperties.primitive — e.g. PRIVATE-KEY-PEM,
	// PUBLIC-KEY, CERTIFICATE-X509.
	primitive string
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
	category      types.Category
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

// regexSkipExts lists file extensions that the regex scanner should skip entirely.
// These produce excessive false positives or are not source code.
var regexSkipExts = map[string]bool{
	".md":       true,
	".markdown": true,
}

// ScanFile scans a single file's content for crypto-related patterns.
func (s *RegexScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Skip files by extension that generate excessive false positives.
	ext := strings.ToLower(filepath.Ext(path))
	if regexSkipExts[ext] {
		return nil, nil
	}

	// Binary DER-encoded certificate files (.der/.cer/.crt) won't pass the
	// text/binary heuristics below, so handle them up front by extension.
	if derCertExts[ext] {
		if findings := s.parseDERCertificates(path, content); len(findings) > 0 {
			return scanner.AnnotateFindings(findings), nil
		}
		// Not a DER cert (e.g. a PEM .crt) — fall through to the text path.
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

	// Build a set of line ranges that are inside PEM blocks.
	// Lines within PEM blocks suppress hex/base64 key material findings.
	pemBlockLines := s.findPEMBlockLines(lines)

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
					MaterialType:       pp.materialType,
					AlgorithmPrimitive: pp.primitive,
				},
				Description: fmt.Sprintf("PEM-encoded %s detected via regex", pp.name),
				RuleID:      pp.ruleID,
				Category:    pp.category,
				Maturity:    types.MaturityStable,
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
					Category:    ap.category,
					Maturity:    types.MaturityStable,
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

		// Suppress hex/base64 findings inside PEM blocks — the PEM header
		// finding itself is kept, but the noisy per-line matches are not.
		if pemBlockLines[lineIdx] {
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
				Category:    types.CategoryInventory,
				Maturity:    types.MaturityStable,
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
				Category:    types.CategoryInventory,
				Maturity:    types.MaturityStable,
				Pass:        1,
			})
		}
	}

	return scanner.AnnotateFindings(findings), nil
}

func (s *RegexScanner) compilePEMPatterns() {
	// PEM blocks are asset-discovery findings: we're cataloguing every key /
	// cert observed in the tree. They live under CategoryInventory so that
	// `--only-inventory` surfaces them. Whether a private key sitting on disk
	// is a security incident is contextual (is the file checked into git? is
	// it a sample?) and belongs to a downstream policy rule, not the
	// detection rule itself. Severity is retained as a signal of how
	// sensitive the discovered asset is.
	s.pemPatterns = []pemPattern{
		{
			re:           regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			name:         "RSA Private Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityHigh,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-rsa-private",
			category:     types.CategoryInventory,
			// PEM-encoded private key on disk. The v2 GT (and CycloneDX 1.7
			// related-crypto-material taxonomy) distinguishes encoded private
			// keys from in-memory PRIVATE-KEY material — use PRIVATE-KEY-PEM
			// so downstream consumers can route the finding to the certs/keys
			// bucket without inspecting the rule ID.
			primitive: "PRIVATE-KEY-PEM",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			name:         "EC Private Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityHigh,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-ec-private",
			category:     types.CategoryInventory,
			primitive:    "PRIVATE-KEY-PEM",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			name:         "Generic Private Key (PKCS#8)",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityHigh,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-pkcs8-private",
			category:     types.CategoryInventory,
			primitive:    "PRIVATE-KEY-PEM",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),
			name:         "Encrypted Private Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityMedium,
			materialType: "private-key",
			ruleID:       "cbom-regex-pem-encrypted-private",
			category:     types.CategoryInventory,
			primitive:    "PRIVATE-KEY-PEM",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`),
			name:         "Public Key",
			assetType:    types.AssetRelatedCryptoMaterial,
			severity:     types.SeverityInfo,
			materialType: "public-key",
			ruleID:       "cbom-regex-pem-public",
			category:     types.CategoryInventory,
			primitive:    "PUBLIC-KEY",
		},
		{
			re:           regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
			name:         "Certificate",
			assetType:    types.AssetCertificate,
			severity:     types.SeverityInfo,
			materialType: "",
			ruleID:       "cbom-regex-pem-certificate",
			category:     types.CategoryInventory,
			primitive:    "CERTIFICATE-X509",
		},
	}
}

func (s *RegexScanner) compileAlgoPatterns() {
	// Broken / weak algorithms -> MEDIUM severity
	brokenAlgos := []struct {
		pattern string
		name    string
		family  string
		prim    string
		quantum types.QuantumStatus
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
			category:      types.CategorySecurity,
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
			category:      types.CategoryInventory,
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
					CertificateFormat:  "PEM",
					AlgorithmPrimitive: "CERTIFICATE-X509",
				},
				Description: "PEM certificate block found but could not be parsed",
				RuleID:      "cbom-regex-pem-certificate-parse",
				Category:    types.CategoryInventory,
				Maturity:    types.MaturityStable,
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
				CertificateFormat:  "PEM",
				AlgorithmPrimitive: "CERTIFICATE-X509",
			},
			Description: "PEM certificate block found but could not be parsed",
			RuleID:      "cbom-regex-pem-certificate-parse",
			Category:    types.CategoryInventory,
			Maturity:    types.MaturityStable,
			Pass:        1,
		})
	}

	return findings
}

// buildCertFinding creates a finding for a successfully parsed X.509 certificate.
func buildCertFinding(cert *x509.Certificate, path string, lineNum int) types.Finding {
	severity := types.SeverityInfo
	state := "active"
	category := types.CategoryInventory
	now := time.Now()
	if now.After(cert.NotAfter) {
		severity = types.SeverityHigh
		state = "expired"
		category = types.CategorySecurity
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		severity = types.SeverityMedium
		state = "expiring-soon"
		category = types.CategorySecurity
	}

	sigAlgo := cert.SignatureAlgorithm.String()
	pubAlgo, pubSize := certPublicKeyInfo(cert)

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
			SubjectName:               cert.Subject.String(),
			IssuerName:                cert.Issuer.String(),
			NotValidBefore:            cert.NotBefore.Format(time.RFC3339),
			NotValidAfter:             cert.NotAfter.Format(time.RFC3339),
			SignatureAlgorithm:        sigAlgo,
			CertificateFormat:         "X.509",
			SubjectPublicKeyAlgorithm: pubAlgo,
			SubjectPublicKeySize:      pubSize,
			CertificateExtensions:     certExtensionSummaries(cert),
			State:                     state,
			AlgorithmPrimitive:        "CERTIFICATE-X509",
		},
		Description: fmt.Sprintf("X.509 certificate for %q signed with %s (expires %s)",
			cert.Subject.CommonName, sigAlgo, cert.NotAfter.Format("2006-01-02")),
		RuleID:   "cbom-regex-pem-certificate-parsed",
		Category: category,
		Maturity: types.MaturityStable,
		Pass:     1,
	}
}

// derCertExts are file extensions that may hold a binary DER-encoded cert.
var derCertExts = map[string]bool{".der": true, ".cer": true, ".crt": true}

// parseDERCertificates parses one or more concatenated DER X.509 certificates
// from raw bytes. Returns nil if the content is not DER (e.g. a PEM file).
func (s *RegexScanner) parseDERCertificates(path string, content []byte) []types.Finding {
	certs, err := x509.ParseCertificates(content)
	if err != nil || len(certs) == 0 {
		return nil
	}
	findings := make([]types.Finding, 0, len(certs))
	for _, c := range certs {
		f := buildCertFinding(c, path, 1)
		f.Properties.CertificateFormat = "DER"
		findings = append(findings, f)
	}
	return findings
}

// certPublicKeyInfo returns the certificate's public-key algorithm name and key
// size in bits, derived from the parsed key (no parameter inference needed).
func certPublicKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	case *dsa.PublicKey:
		if pub.P != nil {
			return "DSA", pub.P.BitLen()
		}
		return "DSA", 0
	default:
		// Fall back to the x509 enum string for unknown key types.
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// certExtensionSummaries renders the security-relevant X.509 extensions
// (KeyUsage, ExtendedKeyUsage, BasicConstraints, SubjectAltName) as compact
// strings for the certificateExtension field.
func certExtensionSummaries(cert *x509.Certificate) []string {
	var out []string
	if ku := keyUsageNames(cert.KeyUsage); len(ku) > 0 {
		out = append(out, "KeyUsage="+strings.Join(ku, ","))
	}
	if eku := extKeyUsageNames(cert.ExtKeyUsage); len(eku) > 0 {
		out = append(out, "ExtendedKeyUsage="+strings.Join(eku, ","))
	}
	if cert.BasicConstraintsValid {
		bc := "BasicConstraints=CA:false"
		if cert.IsCA {
			bc = "BasicConstraints=CA:true"
			if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
				bc += fmt.Sprintf(",pathlen:%d", cert.MaxPathLen)
			}
		}
		out = append(out, bc)
	}
	if san := subjectAltNames(cert); len(san) > 0 {
		out = append(out, "SubjectAltName="+strings.Join(san, ","))
	}
	return out
}

func keyUsageNames(ku x509.KeyUsage) []string {
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var names []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			names = append(names, p.name)
		}
	}
	return names
}

func extKeyUsageNames(ekus []x509.ExtKeyUsage) []string {
	name := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
		x509.ExtKeyUsageAny:             "any",
	}
	var names []string
	for _, e := range ekus {
		if n, ok := name[e]; ok {
			names = append(names, n)
		}
	}
	return names
}

// subjectAltNames collects DNS/IP/email/URI SANs, capped to keep the summary
// compact on certificates with large SAN lists.
func subjectAltNames(cert *x509.Certificate) []string {
	const maxSAN = 10
	var sans []string
	for _, d := range cert.DNSNames {
		sans = append(sans, "DNS:"+d)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, e := range cert.EmailAddresses {
		sans = append(sans, "email:"+e)
	}
	for _, u := range cert.URIs {
		sans = append(sans, "URI:"+u.String())
	}
	if len(sans) > maxSAN {
		extra := len(sans) - maxSAN
		sans = append(sans[:maxSAN], fmt.Sprintf("(+%d more)", extra))
	}
	return sans
}

// pemBeginRe matches any PEM BEGIN header line.
var pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`)

// pemEndRe matches any PEM END footer line.
var pemEndRe = regexp.MustCompile(`-----END [A-Z0-9 ]+-----`)

// findPEMBlockLines scans lines and returns a map of 0-based line indices
// that are inside a PEM block (between BEGIN and END markers, exclusive of the
// BEGIN line but inclusive of content lines and the END line). The BEGIN line
// itself is NOT marked so that PEM header findings are still emitted.
func (s *RegexScanner) findPEMBlockLines(lines [][]byte) map[int]bool {
	result := make(map[int]bool)
	inBlock := false
	for i, line := range lines {
		if !inBlock {
			if pemBeginRe.Match(line) {
				inBlock = true
				// Don't mark the BEGIN line — the PEM header finding should still fire.
				continue
			}
		} else {
			// Mark every line inside the block (including END line).
			result[i] = true
			if pemEndRe.Match(line) {
				inBlock = false
			}
		}
	}
	return result
}

func nextID() string {
	n := findingCounter.Add(1)
	return fmt.Sprintf("REGEX-%04d", n)
}
