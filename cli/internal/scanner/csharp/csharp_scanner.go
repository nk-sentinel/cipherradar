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
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/astrules"
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

	return scanner.AnnotateFindings(findings), nil
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

var dotNetFactoryClasses map[string]dotNetFactoryInfo

// bcEngineT is the value type for bcEngineAlgorithms (BouncyCastle.NET engines).
type bcEngineT struct {
	family    string
	name      string
	primitive string
}

// bcDigestT is the value type for bcDigestAlgorithms (BouncyCastle.NET digests).
type bcDigestT struct {
	family string
	name   string
}

// sslProtocolT is the value type for sslProtocolInfo (SslProtocols enum values).
type sslProtocolT struct {
	name     string
	version  string
	severity types.Severity
}

// The C# Pass-1 detection tables below are DATA, loaded from the embedded
// scanner/ast-rules/csharp.yml at init() and replaceable at scan time via
// --ast-rules-dir (astrules.LoadCSharp). Only the tables (token -> crypto
// semantics) are external; the tree-sitter query machinery stays in Go. The
// local struct types preserve the exact field names the detect sites already
// use, so wiring them from data required no change at the lookup sites. See
// docs/ast-rules-external-design.md.
var (
	// bcEngineAlgorithms maps BouncyCastle.NET engine class names to algorithm info.
	bcEngineAlgorithms map[string]bcEngineT
	// bcDigestAlgorithms maps BouncyCastle.NET digest class names to algorithm info.
	bcDigestAlgorithms map[string]bcDigestT
	// sslProtocolInfo maps SslProtocols enum values to TLS version info.
	sslProtocolInfo map[string]sslProtocolT
)

func init() {
	applyCSharpTables(astrules.MustLoadCSharpEmbedded())
}

// applyCSharpTables (re)populates the package-level detection tables from a
// loaded astrules.CSharpTables. Called at init with the embedded set and again
// by ApplyExternalRules when --ast-rules-dir is given.
func applyCSharpTables(t *astrules.CSharpTables) {
	fc := make(map[string]dotNetFactoryInfo, len(t.FactoryClasses))
	for _, r := range t.FactoryClasses {
		fc[r.Class] = dotNetFactoryInfo{
			family:      r.Family,
			name:        r.Name,
			primitive:   r.Primitive,
			severity:    parseCSharpSeverity(r.Severity),
			ruleTag:     r.RuleTag,
			cryptoFunc:  r.CryptoFunc,
			materialTag: r.MaterialTag,
		}
	}
	dotNetFactoryClasses = fc

	be := make(map[string]bcEngineT, len(t.BCEngines))
	for _, r := range t.BCEngines {
		be[r.Class] = bcEngineT{family: r.Family, name: r.Name, primitive: r.Primitive}
	}
	bcEngineAlgorithms = be

	bd := make(map[string]bcDigestT, len(t.BCDigests))
	for _, r := range t.BCDigests {
		bd[r.Class] = bcDigestT{family: r.Family, name: r.Name}
	}
	bcDigestAlgorithms = bd

	sp := make(map[string]sslProtocolT, len(t.SSLProtocols))
	for _, r := range t.SSLProtocols {
		sp[r.Enum] = sslProtocolT{name: r.Name, version: r.Version, severity: parseCSharpSeverity(r.Severity)}
	}
	sslProtocolInfo = sp
}

// ApplyExternalRules replaces the active C# Pass-1 tables from an external
// --ast-rules-dir. When dir is empty, or has no csharp.yml, the embedded tables
// are restored (per-language fallback). Returns an error only when a present
// csharp.yml is malformed.
func ApplyExternalRules(dir string) error {
	t, err := astrules.LoadCSharp(dir)
	if err != nil {
		return err
	}
	applyCSharpTables(t)
	return nil
}

func parseCSharpSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// ---------------------------------------------------------------------------
// .NET factory-method detection (Xxx.Create())
// ---------------------------------------------------------------------------

// csKeySizeReceiver records a factory finding (e.g. RSA.Create()) whose key
// size may be set on a later `recv.KeySize = N` property assignment.
type csKeySizeReceiver struct {
	varName    string
	findingIdx int
	declByte   uint32
}

func (s *CSharpScanner) detectDotNetCrypto(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding
	var receivers []csKeySizeReceiver

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
		// Track the receiver for a possible later `recv.KeySize = N`.
		if finding.Properties.KeySize == 0 && supportsKeySizeProperty(className) {
			if v, db, ok := receiverVarOfCall(callNode, content); ok {
				receivers = append(receivers, csKeySizeReceiver{v, len(findings) - 1, db})
			}
		}
	}

	s.applyKeySizePropertyAssignments(root, content, cp, findings, receivers)

	return findings
}

func supportsKeySizeProperty(className string) bool {
	switch className {
	case "RSA", "Aes", "TripleDES", "DES", "DSA", "ECDsa", "ECDiffieHellman":
		return true
	default:
		return false
	}
}

// receiverVarOfCall walks up from a method_invocation to recover the variable it
// is assigned to (e.g. `var rsa = RSA.Create()` -> "rsa").
func receiverVarOfCall(callNode *sitter.Node, content []byte) (string, uint32, bool) {
	n := callNode
	for i := 0; i < 4 && n != nil; i++ {
		parent := n.Parent()
		if parent == nil {
			break
		}
		switch parent.Type() {
		case "variable_declarator":
			if nameNode := parent.ChildByFieldName("name"); nameNode != nil && nameNode.Type() == "identifier" {
				return scanner.NodeText(nameNode, content), parent.StartByte(), true
			}
			// Some grammars expose the name as the first identifier child.
			if first := parent.Child(0); first != nil && first.Type() == "identifier" {
				return scanner.NodeText(first, content), parent.StartByte(), true
			}
		case "assignment_expression":
			if leftNode := parent.ChildByFieldName("left"); leftNode != nil && leftNode.Type() == "identifier" {
				return scanner.NodeText(leftNode, content), parent.StartByte(), true
			}
		}
		n = parent
	}
	return "", 0, false
}

// applyKeySizePropertyAssignments patches the KeySize of factory findings from
// later `recv.KeySize = N` property assignments (the C# analog of the JCA
// initialize() idiom).
func (s *CSharpScanner) applyKeySizePropertyAssignments(root *sitter.Node, content []byte, cp *ConstPropagator, findings []types.Finding, receivers []csKeySizeReceiver) {
	if len(receivers) == 0 {
		return
	}
	queryStr := `(assignment_expression
		left: (field_access) @lhs
		right: (_) @rhs)`
	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return
	}
	for _, match := range matches {
		var lhs, rhs *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				lhs = capture.Node
			case 1:
				rhs = capture.Node
			}
		}
		if lhs == nil || rhs == nil || lhs.ChildCount() < 2 {
			continue
		}
		recvNode := lhs.Child(0)
		fieldNode := lhs.Child(int(lhs.ChildCount()) - 1)
		if recvNode == nil || fieldNode == nil || recvNode.Type() != "identifier" {
			continue
		}
		if scanner.NodeText(fieldNode, content) != "KeySize" {
			continue
		}
		size := intFromNode(rhs, content, cp)
		if size <= 0 {
			continue
		}
		recvName := scanner.NodeText(recvNode, content)
		callByte := lhs.StartByte()
		best := -1
		var bestByte uint32
		for i, r := range receivers {
			if r.varName != recvName {
				continue
			}
			if r.declByte <= callByte && (best == -1 || r.declByte > bestByte) {
				best, bestByte = i, r.declByte
			}
		}
		if best == -1 {
			continue
		}
		idx := receivers[best].findingIdx
		findings[idx].Properties.KeySize = size
		if base := findings[idx].Name; base != "" && !strings.ContainsRune(base, '-') {
			findings[idx].Name = fmt.Sprintf("%s-%d", base, size)
		}
	}
}

// intFromNode resolves a node to an integer: a numeric literal, or an
// identifier resolvable via constant propagation.
func intFromNode(n *sitter.Node, content []byte, cp *ConstPropagator) int {
	switch n.Type() {
	case "decimal_integer_literal", "hex_integer_literal":
		v, _ := strconv.Atoi(scanner.NodeText(n, content))
		return v
	case "identifier":
		if val, ok := cp.Resolve(scanner.NodeText(n, content)); ok {
			v, _ := strconv.Atoi(val)
			return v
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// BouncyCastle.NET detection
// ---------------------------------------------------------------------------

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
		// CipherMode.ECB — ECB mode is insecure
		{
			re: regexp.MustCompile(`CipherMode\s*\.\s*ECB\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return &types.Finding{
					ID:        nextFindingID(),
					AssetType: types.AssetAlgorithm,
					Name:      "ECB Mode",
					Location: types.Location{
						File:      path,
						StartLine: line,
						StartCol:  1,
						EndLine:   line,
						EndCol:    1,
					},
					Severity:   types.SeverityHigh,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive: "block-cipher",
						Mode:      "ecb",
					},
					Description: "ECB cipher mode is insecure — does not provide semantic security",
					RuleID:      "cbom-csharp-dotnet-ciphermode-ecb",
					Pass:        1,
				}
			},
		},
		// RSAEncryptionPadding.Pkcs1 — PKCS1v15 padding (padding oracle)
		{
			re: regexp.MustCompile(`RSAEncryptionPadding\s*\.\s*Pkcs1\b`),
			buildResult: func(path string, line int, _ []string) *types.Finding {
				return &types.Finding{
					ID:        nextFindingID(),
					AssetType: types.AssetAlgorithm,
					Name:      "RSA-PKCS1v15",
					Location: types.Location{
						File:      path,
						StartLine: line,
						StartCol:  1,
						EndLine:   line,
						EndCol:    1,
					},
					Severity:   types.SeverityMedium,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:       "pke",
						AlgorithmFamily: "rsa",
						Padding:         "pkcs1v15",
						CryptoFunctions: []string{"encrypt"},
					},
					Description: "RSA PKCS1v15 padding is vulnerable to padding oracle attacks — use OAEP instead",
					RuleID:      "cbom-csharp-dotnet-rsa-pkcs1v15",
					Pass:        1,
				}
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
