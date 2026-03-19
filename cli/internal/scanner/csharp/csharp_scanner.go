// Package csharp detects cryptographic API usage in C# source files.
//
// C# cryptographic APIs come from two main sources:
//   - System.Security.Cryptography (the standard .NET crypto namespace)
//   - BouncyCastle.NET (third-party crypto library)
//
// The System.Security.Cryptography APIs use a factory pattern with
// static Create() methods (e.g. Aes.Create(), RSA.Create(2048)),
// while BouncyCastle.NET uses explicit constructors (e.g. new AesEngine()).
//
// Because there is no Go binding for a tree-sitter C# grammar in
// github.com/smacker/go-tree-sitter, this scanner uses the Java grammar
// as a fallback for constructor-based patterns (BouncyCastle). For the
// .NET factory-method patterns (Xxx.Create()), the Java grammar parses
// these as method_invocation nodes. C#-specific patterns that the Java
// grammar cannot parse (SslProtocols enum, HMACSHA256 constructor without
// "new" keyword, Rfc2898DeriveBytes) are handled via line-based regex
// scanning.
package csharp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	javaLang "github.com/smacker/go-tree-sitter/java"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// CSharpScanner detects cryptographic API usage in C# source files.
// It uses the Java tree-sitter grammar for constructor and method-call
// patterns, supplemented by regex-based detection for C#-specific APIs.
type CSharpScanner struct {
	lang *sitter.Language
}

// New creates a new CSharpScanner instance.
func New() *CSharpScanner {
	return &CSharpScanner{
		lang: javaLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *CSharpScanner) Name() string {
	return "csharp"
}

// Extensions returns the file extensions this scanner handles.
func (s *CSharpScanner) Extensions() []string {
	return []string{".cs"}
}

// ScanFile scans a single C# file's content and returns cryptographic findings.
func (s *CSharpScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
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

	// Detect System.Security.Cryptography factory patterns: Xxx.Create()
	dotNetFindings := s.detectDotNetCrypto(root, path, content, cp)
	findings = append(findings, dotNetFindings...)

	// Detect BouncyCastle.NET constructor patterns
	bcFindings := s.detectBouncyCastle(root, path, content, cp)
	findings = append(findings, bcFindings...)

	// Detect C#-specific patterns via regex (SslStream, HMACSHA256, Rfc2898DeriveBytes, etc.)
	regexFindings := s.detectRegexPatterns(path, content)
	findings = append(findings, regexFindings...)

	return findings, nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// .NET factory class mapping
// ---------------------------------------------------------------------------

// dotNetFactoryClass maps .NET crypto class names to detection metadata.
// These classes use the static Create() factory pattern.
type dotNetFactoryInfo struct {
	family      string
	name        string
	primitive   string
	severity    types.Severity
	ruleTag     string
	cryptoFunc  string
	materialTag string // non-empty for key-material findings
}

var dotNetFactoryClasses = map[string]dotNetFactoryInfo{
	// Symmetric ciphers
	"Aes":       {family: "aes", name: "AES", primitive: "block-cipher", severity: types.SeverityInfo, ruleTag: "aes", cryptoFunc: "encrypt"},
	"TripleDES": {family: "3des", name: "3DES", primitive: "block-cipher", severity: types.SeverityHigh, ruleTag: "3des", cryptoFunc: "encrypt"},
	"DES":       {family: "des", name: "DES", primitive: "block-cipher", severity: types.SeverityHigh, ruleTag: "des", cryptoFunc: "encrypt"},

	// Asymmetric ciphers / key generation
	"RSA":   {family: "rsa", name: "RSA", primitive: "pke", severity: types.SeverityInfo, ruleTag: "rsa", cryptoFunc: "generate"},
	"ECDsa": {family: "ecdsa", name: "ECDSA", primitive: "signature", severity: types.SeverityInfo, ruleTag: "ecdsa", cryptoFunc: "generate"},

	// Hashes
	"SHA256": {family: "sha-256", name: "SHA-256", primitive: "hash", severity: types.SeverityInfo, ruleTag: "sha256", cryptoFunc: "digest"},
	"SHA384": {family: "sha-384", name: "SHA-384", primitive: "hash", severity: types.SeverityInfo, ruleTag: "sha384", cryptoFunc: "digest"},
	"SHA512": {family: "sha-512", name: "SHA-512", primitive: "hash", severity: types.SeverityInfo, ruleTag: "sha512", cryptoFunc: "digest"},
	"SHA1":   {family: "sha1", name: "SHA-1", primitive: "hash", severity: types.SeverityHigh, ruleTag: "sha1", cryptoFunc: "digest"},
	"MD5":    {family: "md5", name: "MD5", primitive: "hash", severity: types.SeverityHigh, ruleTag: "md5", cryptoFunc: "digest"},
}

// ---------------------------------------------------------------------------
// .NET factory-method detection (Xxx.Create())
// ---------------------------------------------------------------------------

func (s *CSharpScanner) detectDotNetCrypto(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for ClassName.Create(...) calls
	// Under the Java grammar, C# method calls parse as method_invocation nodes.
	queryStr := `(method_invocation
		object: (identifier) @cls
		name: (identifier) @method
		arguments: (argument_list) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var clsNode, methodNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0: // @cls
				clsNode = capture.Node
			case 1: // @method
				methodNode = capture.Node
			case 2: // @args
				argsNode = capture.Node
			}
		}
		if clsNode == nil || methodNode == nil {
			continue
		}

		methodName := scanner.NodeText(methodNode, content)
		if methodName != "Create" {
			continue
		}

		className := scanner.NodeText(clsNode, content)
		info, known := dotNetFactoryClasses[className]
		if !known {
			continue
		}

		callNode := getCallNode(methodNode)

		qi := quantum.GetInfo(info.family)

		finding := types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       info.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   info.severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        info.primitive,
				AlgorithmFamily:  info.family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{info.cryptoFunc},
			},
			Description: fmt.Sprintf("%s via %s.Create()", info.name, className),
			RuleID:      fmt.Sprintf("cbom-csharp-dotnet-%s", info.ruleTag),
			Pass:        1,
		}

		// Try to extract key size from Create(keySize) argument for RSA
		if className == "RSA" {
			if keySize := resolveNthArgInt(argsNode, 0, content, cp); keySize > 0 {
				finding.Properties.KeySize = keySize
				finding.Name = fmt.Sprintf("RSA-%d", keySize)
			}
		}

		findings = append(findings, finding)
	}

	return findings
}

// ---------------------------------------------------------------------------
// BouncyCastle.NET detection
// ---------------------------------------------------------------------------

// bcEngineAlgorithms maps BouncyCastle.NET engine class names to algorithm info.
var bcEngineAlgorithms = map[string]struct {
	family    string
	name      string
	primitive string
}{
	"AesEngine":  {family: "aes", name: "AES", primitive: "block-cipher"},
	"DesEngine":  {family: "des", name: "DES", primitive: "block-cipher"},
	"RsaEngine":  {family: "rsa", name: "RSA", primitive: "pke"},
	"AESEngine":  {family: "aes", name: "AES", primitive: "block-cipher"},
	"DESEngine":  {family: "des", name: "DES", primitive: "block-cipher"},
	"RSAEngine":  {family: "rsa", name: "RSA", primitive: "pke"},
	"RC4Engine":  {family: "rc4", name: "RC4", primitive: "stream-cipher"},
	"DESedeEngine": {family: "3des", name: "3DES", primitive: "block-cipher"},
}

// bcDigestAlgorithms maps BouncyCastle.NET digest class names to algorithm info.
var bcDigestAlgorithms = map[string]struct {
	family string
	name   string
}{
	"Sha256Digest":  {family: "sha-256", name: "SHA-256"},
	"MD5Digest":     {family: "md5", name: "MD5"},
	"SHA256Digest":  {family: "sha-256", name: "SHA-256"},
	"Md5Digest":     {family: "md5", name: "MD5"},
	"Sha1Digest":    {family: "sha1", name: "SHA-1"},
	"SHA1Digest":    {family: "sha1", name: "SHA-1"},
}

func (s *CSharpScanner) detectBouncyCastle(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for new XxxEngine(), new XxxDigest()
	queryStr := `(object_creation_expression
		type: (type_identifier) @cls
		arguments: (argument_list) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var clsNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 0 { // @cls
				clsNode = capture.Node
			}
		}
		if clsNode == nil {
			continue
		}

		className := scanner.NodeText(clsNode, content)
		callNode := getObjectCreationNode(clsNode)

		// Check if it's an engine class
		if engineInfo, ok := bcEngineAlgorithms[className]; ok {
			qi := quantum.GetInfo(engineInfo.family)
			severity := cipherSeverity(engineInfo.family)

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       engineInfo.name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   severity,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        engineInfo.primitive,
					AlgorithmFamily:  engineInfo.family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("BouncyCastle %s engine via new %s()", engineInfo.name, className),
				RuleID:      fmt.Sprintf("cbom-csharp-bc-engine-%s", strings.ToLower(engineInfo.family)),
				Pass:        1,
			})
			continue
		}

		// Check if it's a digest class
		if digestInfo, ok := bcDigestAlgorithms[className]; ok {
			qi := quantum.GetInfo(digestInfo.family)
			severity := hashSeverity(digestInfo.family)

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       digestInfo.name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   severity,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  digestInfo.family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("BouncyCastle %s digest via new %s()", digestInfo.name, className),
				RuleID:      fmt.Sprintf("cbom-csharp-bc-digest-%s", strings.ToLower(digestInfo.family)),
				Pass:        1,
			})
			continue
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Regex-based C#-specific pattern detection
// ---------------------------------------------------------------------------

// regexPattern describes a single regex-based detection pattern.
type regexPattern struct {
	re          *regexp.Regexp
	buildResult func(path string, line int, matches []string) *types.Finding
}

var regexPatterns []regexPattern

func init() {
	regexPatterns = []regexPattern{
		// HMACSHA256, HMACSHA384, HMACSHA512 constructor (new HMACSHA256(...))
		{
			re: regexp.MustCompile(`new\s+HMACSHA256\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildHMACFinding(path, line, "HMACSHA256", "sha-256")
			},
		},
		{
			re: regexp.MustCompile(`new\s+HMACSHA384\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildHMACFinding(path, line, "HMACSHA384", "sha-384")
			},
		},
		{
			re: regexp.MustCompile(`new\s+HMACSHA512\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildHMACFinding(path, line, "HMACSHA512", "sha-512")
			},
		},
		// Rfc2898DeriveBytes (PBKDF2)
		{
			re: regexp.MustCompile(`new\s+Rfc2898DeriveBytes\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return &types.Finding{
					ID:        nextFindingID(),
					AssetType: types.AssetAlgorithm,
					Name:      "PBKDF2",
					Location: types.Location{
						File:      path,
						StartLine: line,
						StartCol:  1,
						EndLine:   line,
						EndCol:    1,
					},
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:       "kdf",
						AlgorithmFamily: "pbkdf2",
						CryptoFunctions: []string{"derive"},
					},
					Description: "PBKDF2 key derivation via new Rfc2898DeriveBytes()",
					RuleID:      "cbom-csharp-dotnet-pbkdf2",
					Pass:        1,
				}
			},
		},
		// SslProtocols.Tls13 (TLS 1.3) — must match before shorter variants
		{
			re: regexp.MustCompile(`SslProtocols\s*\.\s*Tls13`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildSslFinding(path, line, "Tls13")
			},
		},
		// SslProtocols.Tls12 (TLS 1.2)
		{
			re: regexp.MustCompile(`SslProtocols\s*\.\s*Tls12`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildSslFinding(path, line, "Tls12")
			},
		},
		// SslProtocols.Tls11 (TLS 1.1)
		{
			re: regexp.MustCompile(`SslProtocols\s*\.\s*Tls11`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildSslFinding(path, line, "Tls11")
			},
		},
		// SslProtocols.Tls (TLS 1.0) — must match after longer variants
		{
			re: regexp.MustCompile(`SslProtocols\s*\.\s*Tls\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return buildSslFinding(path, line, "Tls")
			},
		},
	}
}

// buildHMACFinding constructs a finding for HMAC constructors.
func buildHMACFinding(path string, line int, name, hashFamily string) *types.Finding {
	return &types.Finding{
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      name,
		Location: types.Location{
			File:      path,
			StartLine: line,
			StartCol:  1,
			EndLine:   line,
			EndCol:    1,
		},
		Severity:   types.SeverityInfo,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			Primitive:       "mac",
			AlgorithmFamily: "hmac",
			CryptoFunctions: []string{"mac"},
		},
		Description: fmt.Sprintf("HMAC %s via new %s()", hashFamily, name),
		RuleID:      fmt.Sprintf("cbom-csharp-dotnet-%s", strings.ToLower(name)),
		Pass:        1,
	}
}

// sslProtocolInfo maps SslProtocols enum values to TLS version info.
var sslProtocolInfo = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"Tls":   {name: "TLSv1.0", version: "1.0", severity: types.SeverityHigh},
	"Tls11": {name: "TLSv1.1", version: "1.1", severity: types.SeverityHigh},
	"Tls12": {name: "TLSv1.2", version: "1.2", severity: types.SeverityInfo},
	"Tls13": {name: "TLSv1.3", version: "1.3", severity: types.SeverityInfo},
}

// buildSslFinding constructs a finding for an SslProtocols enum value.
func buildSslFinding(path string, line int, enumVal string) *types.Finding {
	info, known := sslProtocolInfo[enumVal]
	if !known {
		return nil
	}

	return &types.Finding{
		ID:        nextFindingID(),
		AssetType: types.AssetProtocol,
		Name:      info.name,
		Location: types.Location{
			File:      path,
			StartLine: line,
			StartCol:  1,
			EndLine:   line,
			EndCol:    1,
		},
		Severity:   info.severity,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			ProtocolType:    "tls",
			ProtocolVersion: info.version,
		},
		Description: fmt.Sprintf("TLS protocol %s via SslProtocols.%s", info.name, enumVal),
		RuleID:      fmt.Sprintf("cbom-csharp-dotnet-tls%s", strings.ReplaceAll(info.version, ".", "")),
		Pass:        1,
	}
}

func (s *CSharpScanner) detectRegexPatterns(path string, content []byte) []types.Finding {
	var findings []types.Finding

	lines := strings.Split(string(content), "\n")
	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		for _, pat := range regexPatterns {
			matches := pat.re.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			finding := pat.buildResult(path, lineNum, matches)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// getCallNode walks up from a method name node to find the enclosing method_invocation.
func getCallNode(node *sitter.Node) *sitter.Node {
	n := node
	for i := 0; i < 5 && n != nil; i++ {
		if n.Type() == "method_invocation" {
			return n
		}
		n = n.Parent()
	}
	if n == nil {
		return node
	}
	return n
}

// getObjectCreationNode walks up from a type_identifier to find the enclosing object_creation_expression.
func getObjectCreationNode(node *sitter.Node) *sitter.Node {
	n := node
	for i := 0; i < 5 && n != nil; i++ {
		if n.Type() == "object_creation_expression" {
			return n
		}
		n = n.Parent()
	}
	if n == nil {
		return node
	}
	return n
}

// resolveFirstArg extracts the first positional argument value from an argument_list node.
func resolveFirstArg(argsNode *sitter.Node, content []byte, cp *ConstPropagator) (string, types.Confidence) {
	return resolveNthArg(argsNode, 0, content, cp)
}

// resolveNthArg extracts the nth positional argument (0-indexed) from an argument_list node.
func resolveNthArg(argsNode *sitter.Node, n int, content []byte, cp *ConstPropagator) (string, types.Confidence) {
	if argsNode == nil {
		return "", types.ConfidenceLow
	}

	posIdx := 0
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}

		nodeType := child.Type()
		if nodeType == "(" || nodeType == ")" || nodeType == "," {
			continue
		}

		if posIdx == n {
			switch nodeType {
			case "string_literal":
				return unquoteString(child.Content(content)), types.ConfidenceHigh
			case "decimal_integer_literal", "hex_integer_literal":
				return child.Content(content), types.ConfidenceHigh
			case "identifier":
				varName := child.Content(content)
				if val, ok := cp.Resolve(varName); ok {
					return val, types.ConfidenceMedium
				}
				return "", types.ConfidenceLow
			default:
				return "", types.ConfidenceLow
			}
		}
		posIdx++
	}

	return "", types.ConfidenceLow
}

// resolveNthArgInt resolves the nth positional argument (0-indexed) to an integer.
// Returns 0 if unable to resolve.
func resolveNthArgInt(argsNode *sitter.Node, n int, content []byte, cp *ConstPropagator) int {
	val, _ := resolveNthArg(argsNode, n, content, cp)
	if val == "" {
		return 0
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return v
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

// cipherSeverity returns the severity for a cipher algorithm family.
func cipherSeverity(algoFamily string) types.Severity {
	switch algoFamily {
	case "des", "3des", "rc4":
		return types.SeverityHigh
	default:
		return types.SeverityInfo
	}
}

// unquoteString removes surrounding double quotes from a string literal.
func unquoteString(raw string) string {
	if len(raw) < 2 {
		return raw
	}
	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1]
	}
	return raw
}
