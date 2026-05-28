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

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
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
	// protocolType, when set, populates CryptoProperties.ProtocolType for
	// protocol-asset findings (e.g. "tls"). Empty for algorithm findings.
	protocolType string
	// captureMode, when true, instructs ScanFile to extract a block-cipher
	// mode of operation (gcm/cbc/ctr/...) from the matched line and populate
	// CryptoProperties.Mode. Used by package:encrypt AES + Encrypter wrappers.
	captureMode bool
	// skipIfContains, when non-empty, suppresses this pattern's match on any
	// line that also contains the given substring. Used to dedupe the
	// standalone AES(...) detector against the Encrypter(AES(...)) wrapper so
	// the wrapped idiom produces exactly one finding.
	skipIfContains string
	// quantumOverride, when non-empty, sets CryptoProperties.QuantumStatus
	// directly instead of deriving it from family via the quantum table. Used
	// for protocol assets (e.g. TLS) that have no algorithm-family entry.
	quantumOverride types.QuantumStatus
}

// aesModeRE extracts the mode of operation from package:encrypt's
// AESMode.<mode> enum (e.g. "AESMode.gcm" -> "gcm"). It is intentionally
// tied to the AESMode enum so it cannot match unrelated identifiers.
var aesModeRE = regexp.MustCompile(`\bAESMode\.([a-zA-Z0-9]+)`)

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
			if pat.skipIfContains != "" && strings.Contains(resolved, pat.skipIfContains) {
				continue
			}
			if pat.re.MatchString(resolved) {
				qi := quantum.GetInfo(pat.family)

				qStatus := qi.Status
				if pat.quantumOverride != "" {
					qStatus = pat.quantumOverride
				}
				props := types.CryptoProperties{
					Primitive:        pat.primitive,
					AlgorithmFamily:  pat.family,
					QuantumStatus:    qStatus,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  pat.cryptoFuncs,
					ProtocolType:     pat.protocolType,
				}

				name := pat.name
				if pat.captureMode {
					// Extract mode from the resolved line (AESMode.<mode>). When
					// an explicit mode is present, refine the finding name to
					// reflect the AEAD/mode identity (e.g. "AES-GCM").
					if m := aesModeRE.FindStringSubmatch(resolved); m != nil {
						mode := strings.ToLower(m[1])
						props.Mode = mode
						name = pat.name + "-" + strings.ToUpper(mode)
						// GCM/CCM/EAX are authenticated-encryption modes.
						switch mode {
						case "gcm", "ccm", "eax", "ocb", "siv":
							props.Primitive = "ae"
							props.CryptoFunctions = []string{"encrypt", "decrypt", "tag"}
						}
					}
				}

				findings = append(findings, types.Finding{
					ID:        nextFindingID(),
					AssetType: pat.assetType,
					Name:      name,
					Location: types.Location{
						File:      path,
						StartLine: lineIdx + 1,
						StartCol:  1,
						EndLine:   lineIdx + 1,
						EndCol:    len(trimmed),
						Snippet:   trimmed,
					},
					Severity:    pat.severity,
					Confidence:  types.ConfidenceHigh,
					Properties:  props,
					Description: fmt.Sprintf("Dart crypto: %s", name),
					RuleID:      pat.ruleID,
					Pass:        1,
				})
			}
		}
	}

	return scanner.AnnotateFindings(findings), nil
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
		// ECKeyGenerator (pointycastle EC key generation — ECDSA/ECDH keys).
		// Tied to the exact generator constructor so it does not match the
		// ECKeyGeneratorParameters(...) argument on adjacent lines.
		{
			re:          regexp.MustCompile(`\bECKeyGenerator\s*\(`),
			family:      "ecdsa",
			name:        "ECDSA",
			primitive:   "signature",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-eckeygen",
			cryptoFuncs: []string{"keygen"},
			assetType:   types.AssetAlgorithm,
		},
		// Scrypt (pointycastle memory-hard password KDF).
		{
			re:          regexp.MustCompile(`\bScrypt\s*\(`),
			family:      "scrypt",
			name:        "scrypt",
			primitive:   "kdf",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-pointycastle-scrypt",
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

		// Encrypter (package:encrypt general encryption wrapper). When the
		// wrapped cipher declares an AESMode (e.g. AESMode.gcm), the mode is
		// captured and the finding is refined to "AES-<MODE>". This is the
		// primary detector for the common Encrypter(AES(...)) idiom, so the
		// standalone AES(...) pattern below is gated to avoid double findings.
		{
			re:          regexp.MustCompile(`\bEncrypter\s*\(`),
			family:      "aes",
			name:        "AES",
			primitive:   "block-cipher",
			severity:    types.SeverityInfo,
			ruleID:      "cbom-dart-encrypt-encrypter",
			cryptoFuncs: []string{"encrypt"},
			assetType:   types.AssetAlgorithm,
			captureMode: true,
		},
		// AES from package:encrypt used standalone (not wrapped by Encrypter on
		// the same line). Matches AES(Key...) / AES(key...). The negative
		// lookbehind-style guard is emulated by requiring the line not contain
		// "Encrypter(" (handled at match time below) — but to keep the regex
		// self-contained we tie it to the AES(...,key) constructor shape and
		// rely on Encrypter owning the wrapped case.
		{
			re:             regexp.MustCompile(`\bAES\s*\(\s*[Kk]ey\b`),
			family:         "aes",
			name:           "AES",
			primitive:      "block-cipher",
			severity:       types.SeverityInfo,
			ruleID:         "cbom-dart-encrypt-aes",
			cryptoFuncs:    []string{"encrypt", "decrypt"},
			assetType:      types.AssetAlgorithm,
			captureMode:    true,
			skipIfContains: "Encrypter(",
		},

		// -------------------------------------------------------------------
		// dart:io — transport security / protocols
		// -------------------------------------------------------------------

		// SecureSocket / RawSecureSocket / SecureServerSocket are dart:io TLS
		// endpoint primitives. Their presence indicates a TLS protocol usage.
		// The pattern is tied to these exact dart:io class names so it does not
		// match arbitrary identifiers containing "socket".
		{
			re:              regexp.MustCompile(`\b(?:Raw)?Secure(?:Server)?Socket\b`),
			family:          "",
			name:            "TLS",
			primitive:       "",
			severity:        types.SeverityInfo,
			ruleID:          "cbom-dart-io-tls",
			cryptoFuncs:     []string{"tls-handshake"},
			assetType:       types.AssetProtocol,
			protocolType:    "tls",
			quantumOverride: types.QuantumVulnerable,
		},
	}
}
