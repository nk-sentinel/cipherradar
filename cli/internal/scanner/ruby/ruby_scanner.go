// Package ruby detects cryptographic API usage in Ruby source files.
//
// Ruby cryptographic operations come from three main libraries:
//   - OpenSSL (OpenSSL::Cipher, OpenSSL::Digest, OpenSSL::PKey, OpenSSL::SSL)
//   - BCrypt (BCrypt::Password)
//   - Digest (Digest::SHA256, Digest::MD5, etc.)
//
// The scanner uses the tree-sitter Ruby grammar to parse source files and
// match method call patterns, with constant propagation for algorithm
// arguments passed via variables.
package ruby

import (
	"fmt"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	rubyLang "github.com/smacker/go-tree-sitter/ruby"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/astrules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// RubyScanner detects cryptographic API usage in Ruby source files.
type RubyScanner struct {
	lang *sitter.Language
}

// New creates a new RubyScanner instance.
func New() *RubyScanner {
	return &RubyScanner{
		lang: rubyLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *RubyScanner) Name() string {
	return "ruby"
}

// Extensions returns the file extensions this scanner handles.
func (s *RubyScanner) Extensions() []string {
	return []string{".rb"}
}

// ScanFile scans a single Ruby file's content and returns cryptographic findings.
func (s *RubyScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	root, err := scanner.ParseWithTreeSitter(content, s.lang)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Collect constant propagation data
	cp := NewConstPropagator()
	cp.CollectAssignments(root, content)

	var findings []types.Finding

	// Detect OpenSSL::Cipher usage
	findings = append(findings, s.detectOpenSSLCipher(root, path, content, cp)...)

	// Detect OpenSSL::Digest usage
	findings = append(findings, s.detectOpenSSLDigest(root, path, content)...)

	// Detect OpenSSL::PKey usage
	findings = append(findings, s.detectOpenSSLPKey(root, path, content, cp)...)

	// Detect OpenSSL::SSL usage
	findings = append(findings, s.detectOpenSSLSSL(root, path, content)...)

	// Detect BCrypt usage
	findings = append(findings, s.detectBCrypt(root, path, content)...)

	// Detect Digest module usage
	findings = append(findings, s.detectDigest(root, path, content)...)

	return scanner.AnnotateFindings(findings), nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// OpenSSL::Cipher detection
// ---------------------------------------------------------------------------

// The Ruby Pass-1 detection tables are DATA, loaded from the embedded
// scanner/ast-rules/ruby.yml at init() and replaceable at scan time via
// --ast-rules-dir (astrules.LoadRuby). Local struct types preserve the exact
// field names the detect sites use, so wiring them from data needed no change
// at the lookup sites. See docs/ast-rules-external-design.md.

type cipherAlgoT struct {
	family string
	mode   string
	name   string
}

type digestAlgoT struct {
	family string
	name   string
}

var (
	// cipherAlgoMap maps OpenSSL cipher method strings to algorithm details.
	cipherAlgoMap map[string]cipherAlgoT
	// digestAlgoMap maps OpenSSL/Digest class names to algorithm details.
	digestAlgoMap map[string]digestAlgoT
)

func init() {
	applyRubyTables(astrules.MustLoadRubyEmbedded())
}

// applyRubyTables (re)populates the package-level detection tables from a loaded
// astrules.RubyTables. Called at init with the embedded set and again by
// ApplyExternalRules when --ast-rules-dir is given.
func applyRubyTables(t *astrules.RubyTables) {
	ca := make(map[string]cipherAlgoT, len(t.CipherAlgorithms))
	for _, r := range t.CipherAlgorithms {
		ca[r.Method] = cipherAlgoT{family: r.Family, mode: r.Mode, name: r.Name}
	}
	cipherAlgoMap = ca

	da := make(map[string]digestAlgoT, len(t.DigestAlgorithms))
	for _, r := range t.DigestAlgorithms {
		da[r.Key] = digestAlgoT{family: r.Family, name: r.Name}
	}
	digestAlgoMap = da
}

// ApplyExternalRules replaces the active Ruby Pass-1 tables from an external
// --ast-rules-dir. When dir is empty, or has no ruby.yml, the embedded tables
// are restored (per-language fallback). Returns an error only when a present
// ruby.yml is malformed.
func ApplyExternalRules(dir string) error {
	t, err := astrules.LoadRuby(dir)
	if err != nil {
		return err
	}
	applyRubyTables(t)
	return nil
}

func (s *RubyScanner) detectOpenSSLCipher(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Walk the AST looking for method calls that contain OpenSSL::Cipher
	s.walkAST(root, content, func(node *sitter.Node) {
		text := node.Content(content)

		// Match OpenSSL::Cipher.new("algo") or OpenSSL::Cipher::AES.new(...)
		if !strings.Contains(text, "OpenSSL::Cipher") && !strings.Contains(text, "Cipher.new") {
			return
		}

		// Try to extract the algorithm string
		algoStr := extractStringArg(node, content, cp)
		if algoStr == "" {
			// Check the full text for embedded string
			algoStr = extractQuotedString(text)
		}
		if algoStr == "" {
			return
		}

		normalizedAlgo := strings.ToLower(algoStr)
		algoInfo, known := cipherAlgoMap[normalizedAlgo]
		if !known {
			algoInfo = cipherAlgoT{family: normalizedAlgo, mode: "", name: strings.ToUpper(algoStr)}
		}

		qi := quantum.GetInfo(algoInfo.family)
		severity := cipherSeverity(algoInfo.family, algoInfo.mode)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       algoInfo.name,
			Location:   scanner.NodeLocation(node, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "block-cipher",
				AlgorithmFamily:  algoInfo.family,
				Mode:             algoInfo.mode,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt", "decrypt"},
			},
			Description: fmt.Sprintf("OpenSSL::Cipher using %s", algoInfo.name),
			RuleID:      fmt.Sprintf("cbom-ruby-openssl-cipher-%s", sanitizeRuleID(normalizedAlgo)),
			Pass:        1,
		})
	})

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL::Digest detection
// ---------------------------------------------------------------------------

func (s *RubyScanner) detectOpenSSLDigest(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	s.walkAST(root, content, func(node *sitter.Node) {
		text := node.Content(content)

		// Match OpenSSL::Digest::SHA256.new, OpenSSL::Digest.new("SHA256"), etc.
		if !strings.Contains(text, "OpenSSL::Digest") {
			return
		}

		// Try to identify the hash algorithm
		algo := ""
		for name := range digestAlgoMap {
			if strings.Contains(strings.ToLower(text), name) {
				algo = name
				break
			}
		}

		if algo == "" {
			// Try extracting from quoted string arg
			quoted := extractQuotedString(text)
			if quoted != "" {
				algo = strings.ToLower(quoted)
			}
		}

		if algo == "" {
			return
		}

		info, ok := digestAlgoMap[algo]
		if !ok {
			info = digestAlgoT{family: algo, name: strings.ToUpper(algo)}
		}

		qi := quantum.GetInfo(info.family)
		severity := hashSeverity(info.family)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       info.name,
			Location:   scanner.NodeLocation(node, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "hash",
				AlgorithmFamily:  info.family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"digest"},
			},
			Description: fmt.Sprintf("OpenSSL::Digest %s usage", info.name),
			RuleID:      fmt.Sprintf("cbom-ruby-openssl-digest-%s", sanitizeRuleID(algo)),
			Pass:        1,
		})
	})

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL::PKey detection
// ---------------------------------------------------------------------------

func (s *RubyScanner) detectOpenSSLPKey(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	s.walkAST(root, content, func(node *sitter.Node) {
		text := node.Content(content)

		if !strings.Contains(text, "OpenSSL::PKey") {
			return
		}

		// RSA key generation: OpenSSL::PKey::RSA.new(2048) or OpenSSL::PKey::RSA.generate(2048)
		if strings.Contains(text, "RSA") && (strings.Contains(text, ".new") || strings.Contains(text, ".generate")) {
			qi := quantum.GetInfo("rsa")
			keySize := extractIntFromText(text)

			name := "RSA"
			if keySize > 0 {
				name = fmt.Sprintf("RSA-%d", keySize)
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(node, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "pke",
					AlgorithmFamily:  "rsa",
					KeySize:          keySize,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: fmt.Sprintf("RSA key generation via OpenSSL::PKey::RSA (key_size=%d)", keySize),
				RuleID:      "cbom-ruby-openssl-pkey-rsa",
				Pass:        1,
			})
			return
		}

		// EC key: OpenSSL::PKey::EC.new("prime256v1") or .generate("prime256v1")
		if strings.Contains(text, "EC") && (strings.Contains(text, ".new") || strings.Contains(text, ".generate")) {
			qi := quantum.GetInfo("ec")
			curveName := extractQuotedString(text)

			name := "EC"
			if curveName != "" {
				name = fmt.Sprintf("EC-%s", curveName)
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(node, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "key-agree",
					AlgorithmFamily:  "ec",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: fmt.Sprintf("EC key generation via OpenSSL::PKey::EC (%s)", curveName),
				RuleID:      "cbom-ruby-openssl-pkey-ec",
				Pass:        1,
			})
			return
		}

		// DSA: OpenSSL::PKey::DSA.new(2048)
		if strings.Contains(text, "DSA") && (strings.Contains(text, ".new") || strings.Contains(text, ".generate")) {
			keySize := extractIntFromText(text)
			name := "DSA"
			if keySize > 0 {
				name = fmt.Sprintf("DSA-%d", keySize)
			}
			qi := quantum.GetInfo("dsa")

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(node, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "signature",
					AlgorithmFamily:  "dsa",
					KeySize:          keySize,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: "DSA key generation via OpenSSL::PKey::DSA",
				RuleID:      "cbom-ruby-openssl-pkey-dsa",
				Pass:        1,
			})
		}
	})

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL::SSL detection
// ---------------------------------------------------------------------------

func (s *RubyScanner) detectOpenSSLSSL(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	s.walkAST(root, content, func(node *sitter.Node) {
		text := node.Content(content)

		if !strings.Contains(text, "OpenSSL::SSL::SSLContext") {
			return
		}

		if strings.Contains(text, ".new") {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetProtocol,
				Name:       "TLS",
				Location:   scanner.NodeLocation(node, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType: "tls",
				},
				Description: "SSL/TLS context via OpenSSL::SSL::SSLContext.new",
				RuleID:      "cbom-ruby-openssl-ssl-context",
				Pass:        1,
			})
		}
	})

	return findings
}

// ---------------------------------------------------------------------------
// BCrypt detection
// ---------------------------------------------------------------------------

func (s *RubyScanner) detectBCrypt(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	s.walkAST(root, content, func(node *sitter.Node) {
		text := node.Content(content)

		if !strings.Contains(text, "BCrypt::Password") {
			return
		}

		if strings.Contains(text, ".create") || strings.Contains(text, ".new") {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "bcrypt",
				Location:   scanner.NodeLocation(node, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "kdf",
					AlgorithmFamily: "bcrypt",
					CryptoFunctions: []string{"hash"},
				},
				Description: "Password hashing via BCrypt::Password",
				RuleID:      "cbom-ruby-bcrypt-password",
				Pass:        1,
			})
		}
	})

	return findings
}

// ---------------------------------------------------------------------------
// Digest module detection (Digest::SHA256, Digest::MD5, etc.)
// ---------------------------------------------------------------------------

func (s *RubyScanner) detectDigest(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	s.walkAST(root, content, func(node *sitter.Node) {
		text := node.Content(content)

		if !strings.Contains(text, "Digest::") {
			return
		}

		// Map of Digest:: class names
		digestClasses := map[string]struct {
			family string
			name   string
		}{
			"Digest::SHA256": {family: "sha-256", name: "SHA-256"},
			"Digest::SHA384": {family: "sha-384", name: "SHA-384"},
			"Digest::SHA512": {family: "sha-512", name: "SHA-512"},
			"Digest::SHA1":   {family: "sha1", name: "SHA-1"},
			"Digest::MD5":    {family: "md5", name: "MD5"},
		}

		for className, info := range digestClasses {
			if strings.Contains(text, className) {
				qi := quantum.GetInfo(info.family)
				severity := hashSeverity(info.family)

				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       info.name,
					Location:   scanner.NodeLocation(node, path, content),
					Severity:   severity,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:        "hash",
						AlgorithmFamily:  info.family,
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  []string{"digest"},
					},
					Description: fmt.Sprintf("Hash function %s via %s", info.name, className),
					RuleID:      fmt.Sprintf("cbom-ruby-digest-%s", sanitizeRuleID(info.family)),
					Pass:        1,
				})
				break // Only emit one finding per node
			}
		}
	})

	return findings
}

// ---------------------------------------------------------------------------
// AST walking helpers
// ---------------------------------------------------------------------------

// walkAST walks the tree-sitter AST and calls callback for each node that
// could be a method call or relevant expression.
func (s *RubyScanner) walkAST(node *sitter.Node, content []byte, callback func(*sitter.Node)) {
	if node == nil {
		return
	}
	s.walkASTRecursive(node, content, callback)
}

func (s *RubyScanner) walkASTRecursive(node *sitter.Node, content []byte, callback func(*sitter.Node)) {
	if node == nil {
		return
	}

	// Check for relevant node types (method calls, scope resolution, etc.)
	nodeType := node.Type()
	if nodeType == "call" || nodeType == "method_call" || nodeType == "scope_resolution" ||
		nodeType == "assignment" || nodeType == "expression_statement" {
		callback(node)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			s.walkASTRecursive(child, content, callback)
		}
	}
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// extractStringArg walks the node's children looking for a string literal argument.
func extractStringArg(node *sitter.Node, content []byte, cp *ConstPropagator) string {
	if node == nil {
		return ""
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		childType := child.Type()
		if childType == "string" || childType == "string_content" {
			raw := child.Content(content)
			return unquoteRubyString(raw)
		}

		// Recurse into argument list
		if childType == "argument_list" || childType == "arguments" {
			result := extractStringArg(child, content, cp)
			if result != "" {
				return result
			}
		}

		// Check for identifier that can be resolved
		if childType == "identifier" {
			name := child.Content(content)
			if val, ok := cp.Resolve(name); ok {
				return val
			}
		}
	}

	return ""
}

// extractQuotedString extracts the first quoted string from text.
func extractQuotedString(text string) string {
	// Try double quotes first
	for _, quote := range []byte{'"', '\''} {
		start := strings.IndexByte(text, quote)
		if start >= 0 {
			end := strings.IndexByte(text[start+1:], quote)
			if end >= 0 {
				return text[start+1 : start+1+end]
			}
		}
	}
	return ""
}

// extractIntFromText extracts the first integer from parenthesized argument text.
func extractIntFromText(text string) int {
	// Look for numbers in the text
	inNum := false
	numStr := ""
	for _, ch := range text {
		if ch >= '0' && ch <= '9' {
			inNum = true
			numStr += string(ch)
		} else if inNum {
			break
		}
	}
	if numStr == "" {
		return 0
	}
	val := 0
	for _, ch := range numStr {
		val = val*10 + int(ch-'0')
	}
	return val
}

// hashSeverity returns the severity for a hash algorithm family.
func hashSeverity(algoFamily string) types.Severity {
	switch algoFamily {
	case "md5", "sha1":
		return types.SeverityHigh
	default:
		return types.SeverityInfo
	}
}

// cipherSeverity returns the severity for a cipher algorithm + mode combination.
func cipherSeverity(algoFamily, mode string) types.Severity {
	switch algoFamily {
	case "des":
		return types.SeverityHigh
	case "3des":
		return types.SeverityHigh
	case "rc4":
		return types.SeverityHigh
	default:
		if mode == "ecb" {
			return types.SeverityHigh
		}
		return types.SeverityInfo
	}
}

// unquoteRubyString removes surrounding quotes from a Ruby string literal.
func unquoteRubyString(raw string) string {
	if len(raw) < 2 {
		return raw
	}
	if (raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'') {
		return raw[1 : len(raw)-1]
	}
	return raw
}

// sanitizeRuleID converts a string to a safe rule ID component.
func sanitizeRuleID(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "_", "-")
	return s
}
