// Package swift detects cryptographic API usage in Swift source files.
//
// Swift cryptographic operations come from three main frameworks:
//   - CryptoKit (Apple's modern crypto framework: AES.GCM, ChaChaPoly, SHA256, HMAC, P256/P384/P521, Curve25519, SymmetricKey)
//   - CommonCrypto (C-level API: CCCrypt, CCHmac, CC_SHA256, CCKeyDerivationPBKDF)
//   - Security (keychain and certificate: SecKeyCreateRandomKey, SecCertificate)
//
// Because there is no Go binding for a tree-sitter Swift grammar in
// github.com/smacker/go-tree-sitter, this scanner uses regex/line-based
// detection for all patterns. Swift's method call syntax (dot-chained calls,
// trailing closures) does not parse well under any available fallback grammar.
package swift

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// SwiftScanner detects cryptographic API usage in Swift source files.
type SwiftScanner struct {
	cryptoKitPatterns  []cryptoPattern
	commonCryptoRe     []*regexPattern
	securityPatterns   []*regexPattern
}

type cryptoPattern struct {
	re          *regexp.Regexp
	family      string
	name        string
	primitive   string
	severity    types.Severity
	ruleID      string
	cryptoFuncs []string
	assetType   types.AssetType
}

type regexPattern struct {
	re          *regexp.Regexp
	family      string
	name        string
	primitive   string
	severity    types.Severity
	ruleID      string
	cryptoFuncs []string
	assetType   types.AssetType
}

// New creates a new SwiftScanner instance.
func New() *SwiftScanner {
	s := &SwiftScanner{}
	s.initCryptoKitPatterns()
	s.initCommonCryptoPatterns()
	s.initSecurityPatterns()
	return s
}

// Name returns the scanner's language name.
func (s *SwiftScanner) Name() string {
	return "swift"
}

// Extensions returns the file extensions this scanner handles.
func (s *SwiftScanner) Extensions() []string {
	return []string{".swift"}
}

// ScanFile scans a single Swift file's content and returns cryptographic findings.
func (s *SwiftScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Collect constant propagation data
	cp := NewConstPropagator()
	cp.CollectAssignments(content)

	var findings []types.Finding

	lines := bytes.Split(content, []byte("\n"))

	for lineIdx, line := range lines {
		lineStr := string(line)
		trimmed := strings.TrimSpace(lineStr)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Resolve variables in the line
		resolved := cp.ResolveLine(trimmed)

		// Detect CryptoKit patterns
		for _, pat := range s.cryptoKitPatterns {
			if pat.re.MatchString(resolved) {
				qi := quantum.GetInfo(pat.family)
				findings = append(findings, types.Finding{
					ID:        nextFindingID(),
					AssetType: pat.assetType,
					Name:      pat.name,
					Location: types.Location{
						File:      path,
						StartLine: lineIdx + 1,
						StartCol:  1,
						EndLine:   lineIdx + 1,
						EndCol:    len(trimmed),
						Snippet:   trimmed,
					},
					Severity:   pat.severity,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:        pat.primitive,
						AlgorithmFamily:  pat.family,
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  pat.cryptoFuncs,
					},
					Description: fmt.Sprintf("CryptoKit %s usage", pat.name),
					RuleID:      pat.ruleID,
					Pass:        1,
				})
			}
		}

		// Detect CommonCrypto patterns
		for _, pat := range s.commonCryptoRe {
			if pat.re.MatchString(resolved) {
				qi := quantum.GetInfo(pat.family)
				findings = append(findings, types.Finding{
					ID:        nextFindingID(),
					AssetType: pat.assetType,
					Name:      pat.name,
					Location: types.Location{
						File:      path,
						StartLine: lineIdx + 1,
						StartCol:  1,
						EndLine:   lineIdx + 1,
						EndCol:    len(trimmed),
						Snippet:   trimmed,
					},
					Severity:   pat.severity,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:        pat.primitive,
						AlgorithmFamily:  pat.family,
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  pat.cryptoFuncs,
					},
					Description: fmt.Sprintf("CommonCrypto %s usage", pat.name),
					RuleID:      pat.ruleID,
					Pass:        1,
				})
			}
		}

		// Detect Security framework patterns
		for _, pat := range s.securityPatterns {
			if pat.re.MatchString(resolved) {
				qi := quantum.GetInfo(pat.family)
				findings = append(findings, types.Finding{
					ID:        nextFindingID(),
					AssetType: pat.assetType,
					Name:      pat.name,
					Location: types.Location{
						File:      path,
						StartLine: lineIdx + 1,
						StartCol:  1,
						EndLine:   lineIdx + 1,
						EndCol:    len(trimmed),
						Snippet:   trimmed,
					},
					Severity:   pat.severity,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:        pat.primitive,
						AlgorithmFamily:  pat.family,
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  pat.cryptoFuncs,
					},
					Description: fmt.Sprintf("Security framework %s usage", pat.name),
					RuleID:      pat.ruleID,
					Pass:        1,
				})
			}
		}
	}

	return findings, nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// CryptoKit pattern initialization
// ---------------------------------------------------------------------------

func (s *SwiftScanner) initCryptoKitPatterns() {
	s.cryptoKitPatterns = []cryptoPattern{
		// AES-GCM
		{
			re:          regexp.MustCompile(`\bAES\.GCM\.(seal|open|SealedBox)\b`),
			family:      "aes",
			name:        "AES-GCM",
			primitive:   "ae",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-aes-gcm",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// ChaChaPoly
		{
			re:          regexp.MustCompile(`\bChaChaPoly\.(seal|open|SealedBox)\b`),
			family:      "chacha20",
			name:        "ChaChaPoly",
			primitive:   "ae",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-chachapoly",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// SHA256
		{
			re:          regexp.MustCompile(`\bSHA256\.(hash|Digest)\b`),
			family:      "sha-256",
			name:        "SHA-256",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-sha256",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// SHA384
		{
			re:          regexp.MustCompile(`\bSHA384\.(hash|Digest)\b`),
			family:      "sha-384",
			name:        "SHA-384",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-sha384",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// SHA512
		{
			re:          regexp.MustCompile(`\bSHA512\.(hash|Digest)\b`),
			family:      "sha-512",
			name:        "SHA-512",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-sha512",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// HMAC (CryptoKit uses HMAC<SHA256>, HMAC<SHA384>, HMAC<SHA512>)
		{
			re:          regexp.MustCompile(`\bHMAC\s*<\s*SHA256\s*>`),
			family:      "sha-256",
			name:        "HMAC-SHA256",
			primitive:   "mac",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-hmac-sha256",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},
		{
			re:          regexp.MustCompile(`\bHMAC\s*<\s*SHA384\s*>`),
			family:      "sha-384",
			name:        "HMAC-SHA384",
			primitive:   "mac",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-hmac-sha384",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},
		{
			re:          regexp.MustCompile(`\bHMAC\s*<\s*SHA512\s*>`),
			family:      "sha-512",
			name:        "HMAC-SHA512",
			primitive:   "mac",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-hmac-sha512",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},
		// P256 signing/key agreement
		{
			re:          regexp.MustCompile(`\bP256\.Signing\b`),
			family:      "ecdsa",
			name:        "P256-Signing",
			primitive:   "signature",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-p256-signing",
			cryptoFuncs: []string{"sign"},
			assetType:   types.AssetAlgorithm,
		},
		{
			re:          regexp.MustCompile(`\bP256\.KeyAgreement\b`),
			family:      "ecdh",
			name:        "P256-KeyAgreement",
			primitive:   "key-agree",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-p256-keyagreement",
			cryptoFuncs: []string{"key-agree"},
			assetType:   types.AssetAlgorithm,
		},
		// P384 signing/key agreement
		{
			re:          regexp.MustCompile(`\bP384\.Signing\b`),
			family:      "ecdsa",
			name:        "P384-Signing",
			primitive:   "signature",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-p384-signing",
			cryptoFuncs: []string{"sign"},
			assetType:   types.AssetAlgorithm,
		},
		{
			re:          regexp.MustCompile(`\bP384\.KeyAgreement\b`),
			family:      "ecdh",
			name:        "P384-KeyAgreement",
			primitive:   "key-agree",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-p384-keyagreement",
			cryptoFuncs: []string{"key-agree"},
			assetType:   types.AssetAlgorithm,
		},
		// P521 signing/key agreement
		{
			re:          regexp.MustCompile(`\bP521\.Signing\b`),
			family:      "ecdsa",
			name:        "P521-Signing",
			primitive:   "signature",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-p521-signing",
			cryptoFuncs: []string{"sign"},
			assetType:   types.AssetAlgorithm,
		},
		{
			re:          regexp.MustCompile(`\bP521\.KeyAgreement\b`),
			family:      "ecdh",
			name:        "P521-KeyAgreement",
			primitive:   "key-agree",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-p521-keyagreement",
			cryptoFuncs: []string{"key-agree"},
			assetType:   types.AssetAlgorithm,
		},
		// Curve25519
		{
			re:          regexp.MustCompile(`\bCurve25519\.Signing\b`),
			family:      "ed25519",
			name:        "Curve25519-Signing",
			primitive:   "signature",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-curve25519-signing",
			cryptoFuncs: []string{"sign"},
			assetType:   types.AssetAlgorithm,
		},
		{
			re:          regexp.MustCompile(`\bCurve25519\.KeyAgreement\b`),
			family:      "x25519",
			name:        "Curve25519-KeyAgreement",
			primitive:   "key-agree",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-curve25519-keyagreement",
			cryptoFuncs: []string{"key-agree"},
			assetType:   types.AssetAlgorithm,
		},
		// SymmetricKey
		{
			re:          regexp.MustCompile(`\bSymmetricKey\s*\(`),
			family:      "aes",
			name:        "SymmetricKey",
			primitive:   "block-cipher",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-cryptokit-symmetrickey",
			cryptoFuncs: []string{"generate"},
			assetType:   types.AssetRelatedCryptoMaterial,
		},
	}
}

// ---------------------------------------------------------------------------
// CommonCrypto pattern initialization
// ---------------------------------------------------------------------------

func (s *SwiftScanner) initCommonCryptoPatterns() {
	s.commonCryptoRe = []*regexPattern{
		// CCCrypt (symmetric encryption/decryption)
		{
			re:          regexp.MustCompile(`\bCCCrypt\s*\(`),
			family:      "aes",
			name:        "CCCrypt",
			primitive:   "block-cipher",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-commoncrypto-cccrypt",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// CCHmac
		{
			re:          regexp.MustCompile(`\bCCHmac\s*\(`),
			family:      "hmac",
			name:        "CCHmac",
			primitive:   "mac",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-commoncrypto-cchmac",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},
		// CC_SHA256
		{
			re:          regexp.MustCompile(`\bCC_SHA256\s*\(`),
			family:      "sha-256",
			name:        "CC_SHA256",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-commoncrypto-cc-sha256",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// CC_SHA512
		{
			re:          regexp.MustCompile(`\bCC_SHA512\s*\(`),
			family:      "sha-512",
			name:        "CC_SHA512",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-commoncrypto-cc-sha512",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// CC_SHA1 (broken)
		{
			re:          regexp.MustCompile(`\bCC_SHA1\s*\(`),
			family:      "sha1",
			name:        "CC_SHA1",
			primitive:   "hash",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-swift-commoncrypto-cc-sha1",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// CC_MD5 (broken)
		{
			re:          regexp.MustCompile(`\bCC_MD5\s*\(`),
			family:      "md5",
			name:        "CC_MD5",
			primitive:   "hash",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-swift-commoncrypto-cc-md5",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// CCKeyDerivationPBKDF
		{
			re:          regexp.MustCompile(`\bCCKeyDerivationPBKDF\s*\(`),
			family:      "pbkdf2",
			name:        "CCKeyDerivationPBKDF",
			primitive:   "kdf",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-commoncrypto-pbkdf",
			cryptoFuncs: []string{"derive"},
			assetType:   types.AssetAlgorithm,
		},
	}
}

// ---------------------------------------------------------------------------
// Security framework pattern initialization
// ---------------------------------------------------------------------------

func (s *SwiftScanner) initSecurityPatterns() {
	s.securityPatterns = []*regexPattern{
		// SecKeyCreateRandomKey
		{
			re:          regexp.MustCompile(`\bSecKeyCreateRandomKey\s*\(`),
			family:      "rsa",
			name:        "SecKeyCreateRandomKey",
			primitive:   "pke",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-security-seckeycreatereandomkey",
			cryptoFuncs: []string{"generate"},
			assetType:   types.AssetRelatedCryptoMaterial,
		},
		// SecCertificate
		{
			re:          regexp.MustCompile(`\bSecCertificateCreateWithData\s*\(`),
			family:      "x509",
			name:        "SecCertificate",
			primitive:   "",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-swift-security-seccertificate",
			cryptoFuncs: []string{"parse"},
			assetType:   types.AssetCertificate,
		},
	}
}
