// Package rust detects cryptographic API usage in Rust source files.
//
// Rust cryptographic operations span multiple crates: ring (digest, aead,
// agreement, pbkdf2, signature), rustls (ClientConfig, ServerConfig, cipher
// suites), and the openssl crate (ssl, crypto, hash, pkey). The scanner uses
// tree-sitter's Rust grammar to parse source files and match function call
// and method invocation patterns, with constant propagation for algorithm
// arguments passed via variables.
package rust

import (
	"fmt"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	rustLang "github.com/smacker/go-tree-sitter/rust"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// RustScanner detects cryptographic API usage in Rust source files.
type RustScanner struct {
	lang *sitter.Language
}

// New creates a new RustScanner instance.
func New() *RustScanner {
	return &RustScanner{
		lang: rustLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *RustScanner) Name() string {
	return "rust"
}

// Extensions returns the file extensions this scanner handles.
func (s *RustScanner) Extensions() []string {
	return []string{".rs"}
}

// ScanFile scans a single Rust file's content and returns cryptographic findings.
func (s *RustScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	root, err := scanner.ParseWithTreeSitter(content, s.lang)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Collect use declarations for import detection
	uses := s.collectUseDecls(root, content)

	// Collect constant propagation data
	cp := NewConstPropagator()
	cp.CollectAssignments(root, content)

	var findings []types.Finding

	// Detect ring crate usage
	findings = append(findings, s.detectRingDigest(root, path, content, uses)...)
	findings = append(findings, s.detectRingAEAD(root, path, content, uses)...)
	findings = append(findings, s.detectRingAgreement(root, path, content, uses)...)
	findings = append(findings, s.detectRingPBKDF2(root, path, content, uses)...)
	findings = append(findings, s.detectRingSignature(root, path, content, uses)...)

	// Detect rustls crate usage
	findings = append(findings, s.detectRustls(root, path, content, uses)...)

	// Detect openssl crate usage
	findings = append(findings, s.detectOpenSSLCrate(root, path, content, uses)...)

	return findings, nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// Use declaration collection
// ---------------------------------------------------------------------------

// collectUseDecls walks the AST and collects all `use` declarations.
// Returns a set of fully-qualified paths that have been imported.
func (s *RustScanner) collectUseDecls(root *sitter.Node, content []byte) map[string]bool {
	uses := make(map[string]bool)
	s.walkForUseDecls(root, content, uses)
	return uses
}

func (s *RustScanner) walkForUseDecls(node *sitter.Node, content []byte, uses map[string]bool) {
	if node == nil {
		return
	}

	if node.Type() == "use_declaration" {
		text := node.Content(content)
		// Strip "use " prefix and trailing ";"
		text = strings.TrimPrefix(text, "use ")
		text = strings.TrimSuffix(text, ";")
		text = strings.TrimSpace(text)
		uses[text] = true
		// Also store base path for pattern matching
		parts := strings.Split(text, "::")
		if len(parts) > 1 {
			uses[parts[0]] = true
			// Store progressive paths
			for i := 2; i <= len(parts); i++ {
				uses[strings.Join(parts[:i], "::")] = true
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			s.walkForUseDecls(child, content, uses)
		}
	}
}

// hasUsePrefix checks if any use declaration starts with the given prefix.
func hasUsePrefix(uses map[string]bool, prefix string) bool {
	for path := range uses {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ring::digest detection
// ---------------------------------------------------------------------------

// ringDigestAlgorithms maps ring digest algorithm identifiers to findings info.
var ringDigestAlgorithms = map[string]struct {
	name     string
	family   string
	severity types.Severity
}{
	"SHA256": {name: "SHA-256", family: "sha-256", severity: types.SeverityInfo},
	"SHA384": {name: "SHA-384", family: "sha-384", severity: types.SeverityInfo},
	"SHA512": {name: "SHA-512", family: "sha-512", severity: types.SeverityInfo},
	"SHA1":   {name: "SHA-1", family: "sha1", severity: types.SeverityHigh},
}

func (s *RustScanner) detectRingDigest(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	// Look for ring::digest::digest(), ring::digest::Context::new(), digest::digest(), etc.
	// Also match direct calls: digest::digest(&SHA256, data)
	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// Match digest::digest or ring::digest::digest
		if containsAny(callText, "digest::digest(", "digest::Context::new(") {
			// Try to determine the algorithm from arguments
			algoName, algoInfo := s.resolveRingDigestAlgo(callNode, content)
			if algoName != "" {
				qi := quantum.GetInfo(algoInfo.family)
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       algoInfo.name,
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   algoInfo.severity,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:        "hash",
						AlgorithmFamily:  algoInfo.family,
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  []string{"digest"},
					},
					Description: fmt.Sprintf("%s hash via ring::digest", algoInfo.name),
					RuleID:      "cbom-rust-ring-digest",
					Pass:        1,
				})
			} else {
				// Generic digest detection
				qi := quantum.GetInfo("sha-256")
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       "ring-digest",
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceMedium,
					Properties: types.CryptoProperties{
						Primitive:        "hash",
						AlgorithmFamily:  "sha-256",
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  []string{"digest"},
					},
					Description: "Hash digest via ring::digest",
					RuleID:      "cbom-rust-ring-digest",
					Pass:        1,
				})
			}
		}
	}

	return findings
}

func (s *RustScanner) resolveRingDigestAlgo(callNode *sitter.Node, content []byte) (string, struct {
	name     string
	family   string
	severity types.Severity
}) {
	callText := callNode.Content(content)
	for algoID, info := range ringDigestAlgorithms {
		if strings.Contains(callText, algoID) {
			return algoID, info
		}
	}
	return "", struct {
		name     string
		family   string
		severity types.Severity
	}{}
}

// ---------------------------------------------------------------------------
// ring::aead detection
// ---------------------------------------------------------------------------

func (s *RustScanner) detectRingAEAD(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// AEAD algorithms
		aeadPatterns := map[string]struct {
			name   string
			family string
		}{
			"AES_128_GCM":           {name: "AES-128-GCM", family: "aes"},
			"AES_256_GCM":           {name: "AES-256-GCM", family: "aes"},
			"CHACHA20_POLY1305":     {name: "ChaCha20-Poly1305", family: "chacha20"},
		}

		// Match aead::UnboundKey::new, aead::LessSafeKey::new, aead::SealingKey, aead::OpeningKey
		if containsAny(callText, "UnboundKey::new(", "LessSafeKey::new(", "SealingKey::", "OpeningKey::") {
			matched := false
			for algoID, info := range aeadPatterns {
				if strings.Contains(callText, algoID) {
					qi := quantum.GetInfo(info.family)
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       info.name,
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   types.SeverityInfo,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							Primitive:        "ae",
							AlgorithmFamily:  info.family,
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"encrypt"},
						},
						Description: fmt.Sprintf("%s AEAD via ring::aead", info.name),
						RuleID:      "cbom-rust-ring-aead",
						Pass:        1,
					})
					matched = true
					break
				}
			}
			if !matched {
				// Generic AEAD
				qi := quantum.GetInfo("aes")
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       "ring-aead",
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceMedium,
					Properties: types.CryptoProperties{
						Primitive:        "ae",
						AlgorithmFamily:  "aes",
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  []string{"encrypt"},
					},
					Description: "AEAD via ring::aead",
					RuleID:      "cbom-rust-ring-aead",
					Pass:        1,
				})
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// ring::agreement detection
// ---------------------------------------------------------------------------

func (s *RustScanner) detectRingAgreement(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	agreementAlgos := map[string]struct {
		name   string
		family string
	}{
		"X25519":            {name: "X25519", family: "x25519"},
		"ECDH_P256":         {name: "ECDH-P256", family: "ecdh"},
		"ECDH_P384":         {name: "ECDH-P384", family: "ecdh"},
	}

	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// Match agreement::EphemeralPrivateKey::generate, agreement::agree_ephemeral
		if containsAny(callText, "EphemeralPrivateKey::generate(", "agree_ephemeral(") {
			matched := false
			for algoID, info := range agreementAlgos {
				if strings.Contains(callText, algoID) {
					qi := quantum.GetInfo(info.family)
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       info.name,
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   types.SeverityInfo,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							Primitive:        "key-agree",
							AlgorithmFamily:  info.family,
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"keyagree"},
						},
						Description: fmt.Sprintf("%s key agreement via ring::agreement", info.name),
						RuleID:      "cbom-rust-ring-agreement",
						Pass:        1,
					})
					matched = true
					break
				}
			}
			if !matched {
				qi := quantum.GetInfo("ecdh")
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       "ring-agreement",
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceMedium,
					Properties: types.CryptoProperties{
						Primitive:        "key-agree",
						AlgorithmFamily:  "ecdh",
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  []string{"keyagree"},
					},
					Description: "Key agreement via ring::agreement",
					RuleID:      "cbom-rust-ring-agreement",
					Pass:        1,
				})
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// ring::pbkdf2 detection
// ---------------------------------------------------------------------------

func (s *RustScanner) detectRingPBKDF2(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// Match pbkdf2::derive or pbkdf2::verify
		if containsAny(callText, "pbkdf2::derive(", "pbkdf2::verify(") {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "PBKDF2",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "kdf",
					AlgorithmFamily: "pbkdf2",
					CryptoFunctions: []string{"keydrive"},
				},
				Description: "PBKDF2 key derivation via ring::pbkdf2",
				RuleID:      "cbom-rust-ring-pbkdf2",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// ring::signature detection
// ---------------------------------------------------------------------------

func (s *RustScanner) detectRingSignature(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	sigAlgos := map[string]struct {
		name     string
		family   string
		severity types.Severity
	}{
		"ED25519":                   {name: "Ed25519", family: "ed25519", severity: types.SeverityInfo},
		"ECDSA_P256_SHA256_ASN1":    {name: "ECDSA-P256-SHA256", family: "ecdsa", severity: types.SeverityInfo},
		"ECDSA_P256_SHA256_FIXED":   {name: "ECDSA-P256-SHA256", family: "ecdsa", severity: types.SeverityInfo},
		"ECDSA_P384_SHA384_ASN1":    {name: "ECDSA-P384-SHA384", family: "ecdsa", severity: types.SeverityInfo},
		"ECDSA_P384_SHA384_FIXED":   {name: "ECDSA-P384-SHA384", family: "ecdsa", severity: types.SeverityInfo},
		"RSA_PKCS1_SHA256":          {name: "RSA-PKCS1-SHA256", family: "rsa", severity: types.SeverityInfo},
		"RSA_PKCS1_SHA384":          {name: "RSA-PKCS1-SHA384", family: "rsa", severity: types.SeverityInfo},
		"RSA_PKCS1_SHA512":          {name: "RSA-PKCS1-SHA512", family: "rsa", severity: types.SeverityInfo},
		"RSA_PSS_SHA256":            {name: "RSA-PSS-SHA256", family: "rsa", severity: types.SeverityInfo},
		"RSA_PSS_SHA384":            {name: "RSA-PSS-SHA384", family: "rsa", severity: types.SeverityInfo},
		"RSA_PSS_SHA512":            {name: "RSA-PSS-SHA512", family: "rsa", severity: types.SeverityInfo},
	}

	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// Match signature::Ed25519KeyPair::from_pkcs8, signature::RsaKeyPair::from_*, etc.
		if containsAny(callText, "Ed25519KeyPair::", "EcdsaKeyPair::", "RsaKeyPair::") {
			matched := false
			for algoID, info := range sigAlgos {
				if strings.Contains(callText, algoID) {
					qi := quantum.GetInfo(info.family)
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       info.name,
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   info.severity,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							Primitive:        "signature",
							AlgorithmFamily:  info.family,
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"sign"},
						},
						Description: fmt.Sprintf("%s signature via ring::signature", info.name),
						RuleID:      "cbom-rust-ring-signature",
						Pass:        1,
					})
					matched = true
					break
				}
			}
			if !matched {
				// Detect by key pair type
				if strings.Contains(callText, "Ed25519KeyPair::") {
					qi := quantum.GetInfo("ed25519")
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       "Ed25519",
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   types.SeverityInfo,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							Primitive:        "signature",
							AlgorithmFamily:  "ed25519",
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"sign"},
						},
						Description: "Ed25519 signature via ring::signature",
						RuleID:      "cbom-rust-ring-signature",
						Pass:        1,
					})
				} else if strings.Contains(callText, "EcdsaKeyPair::") {
					qi := quantum.GetInfo("ecdsa")
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       "ECDSA",
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   types.SeverityInfo,
						Confidence: types.ConfidenceMedium,
						Properties: types.CryptoProperties{
							Primitive:        "signature",
							AlgorithmFamily:  "ecdsa",
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"sign"},
						},
						Description: "ECDSA signature via ring::signature",
						RuleID:      "cbom-rust-ring-signature",
						Pass:        1,
					})
				} else if strings.Contains(callText, "RsaKeyPair::") {
					qi := quantum.GetInfo("rsa")
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       "RSA",
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   types.SeverityInfo,
						Confidence: types.ConfidenceMedium,
						Properties: types.CryptoProperties{
							Primitive:        "signature",
							AlgorithmFamily:  "rsa",
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"sign"},
						},
						Description: "RSA signature via ring::signature",
						RuleID:      "cbom-rust-ring-signature",
						Pass:        1,
					})
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// rustls detection
// ---------------------------------------------------------------------------

func (s *RustScanner) detectRustls(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// ClientConfig::builder / ServerConfig::builder
		if containsAny(callText, "ClientConfig::builder(", "ServerConfig::builder(") {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetProtocol,
				Name:       "TLS",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType: "tls",
				},
				Description: "TLS configuration via rustls",
				RuleID:      "cbom-rust-rustls-config",
				Pass:        1,
			})
		}
	}

	// Look for cipher suite references in the source
	cipherSuites := map[string]struct {
		name   string
		family string
	}{
		"TLS13_AES_256_GCM_SHA384":        {name: "AES-256-GCM", family: "aes"},
		"TLS13_AES_128_GCM_SHA256":        {name: "AES-128-GCM", family: "aes"},
		"TLS13_CHACHA20_POLY1305_SHA256":   {name: "ChaCha20-Poly1305", family: "chacha20"},
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {name: "AES-256-GCM", family: "aes"},
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {name: "AES-128-GCM", family: "aes"},
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": {name: "ChaCha20-Poly1305", family: "chacha20"},
	}

	contentStr := string(content)
	for suiteID, info := range cipherSuites {
		if strings.Contains(contentStr, suiteID) {
			qi := quantum.GetInfo(info.family)
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       info.name,
				Location:   types.Location{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1},
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					Primitive:        "ae",
					AlgorithmFamily:  info.family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CipherSuites:     []string{suiteID},
				},
				Description: fmt.Sprintf("Cipher suite %s via rustls", suiteID),
				RuleID:      "cbom-rust-rustls-cipher-suite",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// openssl crate detection
// ---------------------------------------------------------------------------

func (s *RustScanner) detectOpenSSLCrate(root *sitter.Node, path string, content []byte, uses map[string]bool) []types.Finding {
	var findings []types.Finding

	for _, callNode := range findAllCallExprs(root, content) {
		callText := callNode.Content(content)

		// openssl::ssl — SslConnector::builder, SslAcceptor::mozilla_intermediate
		if containsAny(callText, "SslConnector::builder(", "SslAcceptor::mozilla_intermediate(", "SslAcceptor::mozilla_modern(") {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetProtocol,
				Name:       "TLS",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType: "tls",
				},
				Description: "TLS via openssl crate",
				RuleID:      "cbom-rust-openssl-ssl",
				Pass:        1,
			})
		}

		// openssl::hash — MessageDigest::sha256, MessageDigest::md5, etc.
		if strings.Contains(callText, "MessageDigest::") {
			digestAlgos := map[string]struct {
				name     string
				family   string
				severity types.Severity
			}{
				"MessageDigest::sha256(": {name: "SHA-256", family: "sha-256", severity: types.SeverityInfo},
				"MessageDigest::sha384(": {name: "SHA-384", family: "sha-384", severity: types.SeverityInfo},
				"MessageDigest::sha512(": {name: "SHA-512", family: "sha-512", severity: types.SeverityInfo},
				"MessageDigest::sha1(":   {name: "SHA-1", family: "sha1", severity: types.SeverityHigh},
				"MessageDigest::md5(":    {name: "MD5", family: "md5", severity: types.SeverityHigh},
			}

			for pattern, info := range digestAlgos {
				if strings.Contains(callText, pattern) {
					qi := quantum.GetInfo(info.family)
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       info.name,
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   info.severity,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							Primitive:        "hash",
							AlgorithmFamily:  info.family,
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"digest"},
						},
						Description: fmt.Sprintf("%s hash via openssl crate", info.name),
						RuleID:      "cbom-rust-openssl-hash",
						Pass:        1,
					})
					break
				}
			}
		}

		// openssl::pkey — PKey::rsa, PKey::ec, PKey::generate
		if containsAny(callText, "Rsa::generate(", "PKey::from_rsa(") {
			qi := quantum.GetInfo("rsa")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "RSA",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "pke",
					AlgorithmFamily:  "rsa",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: "RSA key generation via openssl crate",
				RuleID:      "cbom-rust-openssl-rsa",
				Pass:        1,
			})
		}

		// openssl::symm — Cipher::aes_256_cbc, Cipher::aes_128_gcm, etc.
		if strings.Contains(callText, "Cipher::") {
			symmAlgos := map[string]struct {
				name   string
				family string
				mode   string
			}{
				"Cipher::aes_256_cbc(":  {name: "AES-256-CBC", family: "aes", mode: "cbc"},
				"Cipher::aes_128_cbc(":  {name: "AES-128-CBC", family: "aes", mode: "cbc"},
				"Cipher::aes_256_gcm(":  {name: "AES-256-GCM", family: "aes", mode: "gcm"},
				"Cipher::aes_128_gcm(":  {name: "AES-128-GCM", family: "aes", mode: "gcm"},
				"Cipher::aes_256_ctr(":  {name: "AES-256-CTR", family: "aes", mode: "ctr"},
				"Cipher::des_cbc(":      {name: "DES-CBC", family: "des", mode: "cbc"},
				"Cipher::des_ecb(":      {name: "DES-ECB", family: "des", mode: "ecb"},
				"Cipher::rc4(":          {name: "RC4", family: "rc4", mode: ""},
			}

			for pattern, info := range symmAlgos {
				if strings.Contains(callText, pattern) {
					qi := quantum.GetInfo(info.family)
					severity := types.SeverityInfo
					if info.family == "des" || info.family == "rc4" {
						severity = types.SeverityHigh
					}
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetAlgorithm,
						Name:       info.name,
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   severity,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							Primitive:        "block-cipher",
							AlgorithmFamily:  info.family,
							Mode:             info.mode,
							QuantumStatus:    qi.Status,
							NistQuantumLevel: qi.NistLevel,
							CryptoFunctions:  []string{"encrypt"},
						},
						Description: fmt.Sprintf("%s via openssl crate", info.name),
						RuleID:      "cbom-rust-openssl-symm",
						Pass:        1,
					})
					break
				}
			}
		}

		// openssl::sign — Signer::new, Verifier::new
		if containsAny(callText, "Signer::new(", "Verifier::new(") {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "openssl-sign",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					Primitive:       "signature",
					AlgorithmFamily: "rsa",
					CryptoFunctions: []string{"sign"},
				},
				Description: "Digital signature via openssl crate",
				RuleID:      "cbom-rust-openssl-sign",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Tree-sitter helpers
// ---------------------------------------------------------------------------

// findAllCallExprs collects all call_expression nodes in the AST.
func findAllCallExprs(root *sitter.Node, content []byte) []*sitter.Node {
	var nodes []*sitter.Node
	walkForCallExprs(root, content, &nodes)
	return nodes
}

func walkForCallExprs(node *sitter.Node, content []byte, nodes *[]*sitter.Node) {
	if node == nil {
		return
	}

	if node.Type() == "call_expression" {
		*nodes = append(*nodes, node)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			walkForCallExprs(child, content, nodes)
		}
	}
}

// containsAny checks if the text contains any of the given substrings.
func containsAny(text string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(text, sub) {
			return true
		}
	}
	return false
}
