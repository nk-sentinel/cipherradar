// Package regex provides a language-agnostic regex scanner that detects crypto
// patterns (PEM headers, algorithm names, high-entropy strings) in any file.
package regex

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/hhrutter/pkcs7"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/certutil"
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
		// No parseable DER cert. If there is no PEM block for the text path to
		// try, this is opaque/corrupt DER cert material — surface it rather than
		// letting the binary heuristics silently drop it (coverage honesty).
		if !bytes.Contains(content, []byte("-----BEGIN")) {
			return scanner.AnnotateFindings([]types.Finding{
				unparsedCertFinding(path, "DER", "not a valid DER X.509 certificate"),
			}), nil
		}
		// Otherwise (e.g. a PEM .crt) — fall through to the text path.
	}

	// PKCS#7 certificate bundles / chains (.p7b/.p7c), DER or PEM-wrapped.
	if pkcs7Exts[ext] {
		if findings := s.parsePKCS7Certificates(path, content); len(findings) > 0 {
			return scanner.AnnotateFindings(findings), nil
		}
		// A .p7b/.p7c that yields no certs is opaque bundle material — surface it.
		return scanner.AnnotateFindings([]types.Finding{
			unparsedCertFinding(path, "PKCS7", "not a valid PKCS#7 certificate bundle"),
		}), nil
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
			// Skip Subresource-Integrity / npm-lockfile integrity hashes
			// (e.g. "integrity": "sha512-<base64>"). These are download
			// digests, not key material. We key off the value SHAPE — a
			// sha256-/sha384-/sha512- prefix immediately before the match —
			// never the field name, so genuine keys are unaffected.
			if looksLikeSRI(line, loc[0]) {
				continue
			}
			// Skip base64 that is itself an X.509 certificate. Such values
			// (e.g. a Kubernetes Secret's tls.crt / ca.crt) are already
			// inventoried as certificates by the config-file / PEM cert path,
			// so reporting them again as "unknown key material" double-counts
			// the same asset (issue #70). We key off the decoded SHAPE (it
			// parses as a DER cert), never the field name.
			if decodesToCertificate(line[loc[0]:loc[1]]) {
				continue
			}
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
		// NOTE: BEGIN CERTIFICATE is intentionally NOT a pemPattern. PEM
		// certificate blocks are handled exclusively by parseCertificateBlocks
		// (called from ScanFile), which emits exactly one finding per block —
		// fully parsed (subject/issuer/extensions/format) when valid, or
		// "unparseable" otherwise. A generic regex pattern here would emit a
		// second, bare "Certificate" finding for the same bytes (double-count).
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
		{`\bSHA-?256\b`, "SHA-256", "sha", "hash", types.QuantumSafe},
		{`\bAES-?128\b`, "AES-128", "aes", "block-cipher", types.QuantumSafe},
		{`\bAES-?256\b`, "AES-256", "aes", "block-cipher", types.QuantumSafe},
		// RSA is quantum-vulnerable (Shor); it lives in this list only because it
		// is not a *broken* primitive. SHA-256/AES-128/AES-256 are quantum-safe
		// (≥128-bit PQ security) — labeling them vulnerable produced a false HNDL
		// migration priority on quantum-safe inventory.
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

// looksLikeSRI reports whether the base64 match starting at `start` is the
// digest of a Subresource-Integrity value, i.e. immediately preceded by a
// `sha256-`, `sha384-`, or `sha512-` prefix (case-insensitive). The `-` is not
// in the base64 character class, so the regex match begins exactly after it.
func looksLikeSRI(line []byte, start int) bool {
	const prefixLen = 7 // len("sha512-")
	if start < prefixLen || line[start-1] != '-' {
		return false
	}
	algo := strings.ToLower(string(line[start-prefixLen : start-1]))
	return algo == "sha256" || algo == "sha384" || algo == "sha512"
}

// minCertB64Len is a cheap lower bound below which a base64 token cannot be an
// X.509 certificate — even a minimal self-signed cert is several hundred DER
// bytes. It lets us skip the decode+parse for the common short high-entropy
// tokens that dominate the base64-key matches.
const minCertB64Len = 200

// decodesToCertificate reports whether a base64 token decodes to a parseable
// DER X.509 certificate. Certificate values embedded as base64 (e.g. a
// Kubernetes Secret's tls.crt) are already inventoried by the certificate
// path, so the generic entropy rule must not also report them as opaque key
// material (issue #70 double-count). Matching is purely by decoded shape.
func decodesToCertificate(b64 []byte) bool {
	if len(b64) < minCertB64Len {
		return false
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(b64), "="))
	if err != nil {
		return false
	}
	// The decoded bytes may be a DER certificate directly, or PEM text — a
	// Kubernetes TLS Secret stores tls.crt as base64 of the PEM block, so
	// decoding yields "-----BEGIN CERTIFICATE-----...", not raw DER.
	if _, err := x509.ParseCertificate(raw); err == nil {
		return true
	}
	if block, _ := pem.Decode(raw); block != nil && block.Type == "CERTIFICATE" {
		if _, err := x509.ParseCertificate(block.Bytes); err == nil {
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

// unparsedCertFinding surfaces certificate-routed material (a .der/.cer/.crt or
// .p7b/.p7c file) that could not be parsed, so opaque/corrupt/unsupported cert
// files still appear in the inventory instead of being silently dropped. This
// mirrors the keystore presence-finding pattern for coverage honesty.
func unparsedCertFinding(path, format, reason string) types.Finding {
	return types.Finding{
		ID:        nextID(),
		AssetType: types.AssetCertificate,
		Name:      "Certificate (unparsed)",
		Location: types.Location{
			File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1,
		},
		Severity:   types.SeverityInfo,
		Confidence: types.ConfidenceLow,
		Properties: types.CryptoProperties{
			CertificateFormat:  format,
			AlgorithmPrimitive: "CERTIFICATE-X509",
			State:              "unparsed",
		},
		Description: fmt.Sprintf("%s certificate material found but could not be parsed (%s)", format, reason),
		RuleID:      "cbom-cert-unparsed",
		Category:    types.CategoryInventory,
		Maturity:    types.MaturityStable,
		Pass:        1,
	}
}

// buildCertFinding creates a finding for a successfully parsed X.509 certificate.
func buildCertFinding(cert *x509.Certificate, path string, lineNum int) types.Finding {
	return certutil.BuildFinding(cert, path, lineNum, nextID,
		"cbom-regex-pem-certificate-parsed", "X.509", "-----BEGIN CERTIFICATE-----",
		"X.509 certificate for ")
}

// derCertExts are file extensions that may hold a binary DER-encoded cert.
var derCertExts = map[string]bool{".der": true, ".cer": true, ".crt": true}

// pkcs7Exts are PKCS#7 certificate-bundle extensions.
var pkcs7Exts = map[string]bool{".p7b": true, ".p7c": true}

// parsePKCS7Certificates parses a PKCS#7 bundle (DER or PEM-wrapped) and emits a
// finding per embedded certificate.
func (s *RegexScanner) parsePKCS7Certificates(path string, content []byte) []types.Finding {
	der := content
	if block, _ := pem.Decode(content); block != nil {
		der = block.Bytes
	}
	p7, err := pkcs7.Parse(der)
	if err != nil || p7 == nil || len(p7.Certificates) == 0 {
		return nil
	}
	findings := make([]types.Finding, 0, len(p7.Certificates))
	for _, c := range p7.Certificates {
		f := buildCertFinding(c, path, 1)
		f.Properties.CertificateFormat = "PKCS7"
		findings = append(findings, f)
	}
	return findings
}

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
