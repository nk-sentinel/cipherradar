// Package dart detects cryptographic API usage in Dart source files.
//
// Dart cryptographic operations come from three main packages:
//   - package:crypto (sha256.convert, sha1.convert, md5.convert, Hmac)
//   - pointycastle (AESFastEngine, RSAEngine, SHA256Digest, PBKDF2KeyDerivator, FortunaRandom)
//   - package:encrypt (Encrypter, AES)
//
// Because there is no tree-sitter grammar available for Dart, this scanner
// uses regex/line-based detection (similar to the config scanner pattern).
package dart

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

// DartScanner detects cryptographic API usage in Dart source files.
type DartScanner struct {
	patterns []dartPattern
}

type dartPattern struct {
	re          *regexp.Regexp
	family      string
	name        string
	primitive   string
	severity    types.Severity
	ruleID      string
	cryptoFuncs []string
	assetType   types.AssetType
}

// New creates a new DartScanner instance with all patterns precompiled.
func New() *DartScanner {
	s := &DartScanner{}
	s.initPatterns()
	return s
}

// Name returns the scanner's language name.
func (s *DartScanner) Name() string {
	return "dart"
}

// Extensions returns the file extensions this scanner handles.
func (s *DartScanner) Extensions() []string {
	return []string{".dart"}
}

// ScanFile scans a single Dart file's content and returns cryptographic findings.
func (s *DartScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
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

		for _, pat := range s.patterns {
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
					Description: fmt.Sprintf("Dart crypto: %s", pat.name),
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
// Pattern initialization
// ---------------------------------------------------------------------------

func (s *DartScanner) initPatterns() {
	s.patterns = []dartPattern{
		// -------------------------------------------------------------------
		// package:crypto
		// -------------------------------------------------------------------

		// sha256.convert
		{
			re:          regexp.MustCompile(`\bsha256\.convert\b`),
			family:      "sha-256",
			name:        "SHA-256",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-crypto-sha256",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// sha384.convert
		{
			re:          regexp.MustCompile(`\bsha384\.convert\b`),
			family:      "sha-384",
			name:        "SHA-384",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-crypto-sha384",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// sha512.convert
		{
			re:          regexp.MustCompile(`\bsha512\.convert\b`),
			family:      "sha-512",
			name:        "SHA-512",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-crypto-sha512",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// sha1.convert (broken)
		{
			re:          regexp.MustCompile(`\bsha1\.convert\b`),
			family:      "sha1",
			name:        "SHA-1",
			primitive:   "hash",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-crypto-sha1",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// md5.convert (broken)
		{
			re:          regexp.MustCompile(`\bmd5\.convert\b`),
			family:      "md5",
			name:        "MD5",
			primitive:   "hash",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-crypto-md5",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// Hmac(sha256, key)
		{
			re:          regexp.MustCompile(`\bHmac\s*\(\s*sha256\b`),
			family:      "sha-256",
			name:        "HMAC-SHA256",
			primitive:   "mac",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-crypto-hmac-sha256",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},
		// Hmac(sha1, key)
		{
			re:          regexp.MustCompile(`\bHmac\s*\(\s*sha1\b`),
			family:      "sha1",
			name:        "HMAC-SHA1",
			primitive:   "mac",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-crypto-hmac-sha1",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},
		// Hmac(md5, key)
		{
			re:          regexp.MustCompile(`\bHmac\s*\(\s*md5\b`),
			family:      "md5",
			name:        "HMAC-MD5",
			primitive:   "mac",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-crypto-hmac-md5",
			cryptoFuncs: []string{"mac"},
			assetType:   types.AssetAlgorithm,
		},

		// -------------------------------------------------------------------
		// pointycastle
		// -------------------------------------------------------------------

		// AESFastEngine (also AESEngine)
		{
			re:          regexp.MustCompile(`\bAES(?:Fast)?Engine\s*\(`),
			family:      "aes",
			name:        "AES",
			primitive:   "block-cipher",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-aes",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// RSAEngine
		{
			re:          regexp.MustCompile(`\bRSAEngine\s*\(`),
			family:      "rsa",
			name:        "RSA",
			primitive:   "pke",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-rsa",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// SHA256Digest
		{
			re:          regexp.MustCompile(`\bSHA256Digest\s*\(`),
			family:      "sha-256",
			name:        "SHA-256",
			primitive:   "hash",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-sha256",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// SHA1Digest (broken)
		{
			re:          regexp.MustCompile(`\bSHA1Digest\s*\(`),
			family:      "sha1",
			name:        "SHA-1",
			primitive:   "hash",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-pointycastle-sha1",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// MD5Digest (broken)
		{
			re:          regexp.MustCompile(`\bMD5Digest\s*\(`),
			family:      "md5",
			name:        "MD5",
			primitive:   "hash",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-pointycastle-md5",
			cryptoFuncs: []string{"digest"},
			assetType:   types.AssetAlgorithm,
		},
		// PBKDF2KeyDerivator
		{
			re:          regexp.MustCompile(`\bPBKDF2KeyDerivator\s*\(`),
			family:      "pbkdf2",
			name:        "PBKDF2",
			primitive:   "kdf",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-pbkdf2",
			cryptoFuncs: []string{"derive"},
			assetType:   types.AssetAlgorithm,
		},
		// FortunaRandom
		{
			re:          regexp.MustCompile(`\bFortunaRandom\s*\(`),
			family:      "fortuna",
			name:        "FortunaRandom",
			primitive:   "random",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-fortuna",
			cryptoFuncs: []string{"generate"},
			assetType:   types.AssetAlgorithm,
		},
		// DESEngine (broken)
		{
			re:          regexp.MustCompile(`\bDESEngine\s*\(`),
			family:      "des",
			name:        "DES",
			primitive:   "block-cipher",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-pointycastle-des",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// RC4Engine (broken)
		{
			re:          regexp.MustCompile(`\bRC4Engine\s*\(`),
			family:      "rc4",
			name:        "RC4",
			primitive:   "stream-cipher",
			severity:    types.SeverityHigh,
			ruleID:      "cbom-dart-pointycastle-rc4",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},

		// -------------------------------------------------------------------
		// package:encrypt
		// -------------------------------------------------------------------

		// Encrypter (general encryption wrapper)
		{
			re:          regexp.MustCompile(`\bEncrypter\s*\(`),
			family:      "aes",
			name:        "Encrypter",
			primitive:   "block-cipher",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-encrypt-encrypter",
			cryptoFuncs: []string{"encrypt"},
			assetType:   types.AssetAlgorithm,
		},
		// AES from package:encrypt (AES mode usage)
		{
			re:          regexp.MustCompile(`\bAES\s*\(\s*key\b`),
			family:      "aes",
			name:        "AES",
			primitive:   "block-cipher",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-encrypt-aes",
			cryptoFuncs: []string{"encrypt", "decrypt"},
			assetType:   types.AssetAlgorithm,
		},
	}
}
