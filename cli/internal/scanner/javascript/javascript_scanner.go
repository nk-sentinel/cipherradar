package javascript

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	jsLang "github.com/smacker/go-tree-sitter/javascript"
	tsLang "github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// JSScanner detects cryptographic API usage in JavaScript and TypeScript source files.
type JSScanner struct {
	jsLang *sitter.Language
	tsLang *sitter.Language
}

// New creates a new JSScanner instance.
func New() *JSScanner {
	return &JSScanner{
		jsLang: jsLang.GetLanguage(),
		tsLang: tsLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *JSScanner) Name() string {
	return "javascript"
}

// Extensions returns the file extensions this scanner handles.
func (s *JSScanner) Extensions() []string {
	return []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
}

// langForFile returns the appropriate tree-sitter language for a given file path.
func (s *JSScanner) langForFile(path string) *sitter.Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".ts", ".tsx":
		return s.tsLang
	default:
		return s.jsLang
	}
}

// ScanFile scans a single JavaScript/TypeScript file's content and returns cryptographic findings.
func (s *JSScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	lang := s.langForFile(path)

	root, err := scanner.ParseWithTreeSitter(content, lang)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Collect constant propagation data
	cp := NewConstPropagator()
	cp.CollectAssignments(root, content)

	var findings []types.Finding

	// Detect Node.js crypto module usage
	cryptoFindings := s.detectNodeCrypto(root, path, content, cp, lang)
	findings = append(findings, cryptoFindings...)

	// Detect jsonwebtoken usage
	jwtFindings := s.detectJWT(root, path, content, cp, lang)
	findings = append(findings, jwtFindings...)

	// Detect node-forge usage
	forgeFindings := s.detectForge(root, path, content, cp, lang)
	findings = append(findings, forgeFindings...)

	// Detect Web Crypto API usage
	webCryptoFindings := s.detectWebCrypto(root, path, content, cp, lang)
	findings = append(findings, webCryptoFindings...)

	return findings, nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// Node.js crypto module detection
// ---------------------------------------------------------------------------

// hashAlgorithms maps Node.js crypto hash algorithm strings to algorithm families.
var hashAlgorithms = map[string]struct {
	family string
	name   string
}{
	"md5":    {family: "md5", name: "MD5"},
	"sha1":   {family: "sha1", name: "SHA-1"},
	"sha224": {family: "sha-256", name: "SHA-224"},
	"sha256": {family: "sha-256", name: "SHA-256"},
	"sha384": {family: "sha-384", name: "SHA-384"},
	"sha512": {family: "sha-512", name: "SHA-512"},
}

// cipherAlgorithms maps Node.js crypto cipher strings to algorithm info.
var cipherAlgorithms = map[string]struct {
	family    string
	name      string
	mode      string
	primitive string
	keySize   int
}{
	"aes-128-cbc": {family: "aes", name: "AES-128-CBC", mode: "cbc", primitive: "block-cipher", keySize: 128},
	"aes-128-gcm": {family: "aes", name: "AES-128-GCM", mode: "gcm", primitive: "ae", keySize: 128},
	"aes-128-ecb": {family: "aes", name: "AES-128-ECB", mode: "ecb", primitive: "block-cipher", keySize: 128},
	"aes-192-cbc": {family: "aes", name: "AES-192-CBC", mode: "cbc", primitive: "block-cipher", keySize: 192},
	"aes-192-gcm": {family: "aes", name: "AES-192-GCM", mode: "gcm", primitive: "ae", keySize: 192},
	"aes-256-cbc": {family: "aes", name: "AES-256-CBC", mode: "cbc", primitive: "block-cipher", keySize: 256},
	"aes-256-gcm": {family: "aes", name: "AES-256-GCM", mode: "gcm", primitive: "ae", keySize: 256},
	"aes-256-ecb": {family: "aes", name: "AES-256-ECB", mode: "ecb", primitive: "block-cipher", keySize: 256},
	"aes-256-ctr": {family: "aes", name: "AES-256-CTR", mode: "ctr", primitive: "block-cipher", keySize: 256},
	"des":         {family: "des", name: "DES", mode: "", primitive: "block-cipher", keySize: 56},
	"des-cbc":     {family: "des", name: "DES-CBC", mode: "cbc", primitive: "block-cipher", keySize: 56},
	"des-ecb":     {family: "des", name: "DES-ECB", mode: "ecb", primitive: "block-cipher", keySize: 56},
	"des-ede3":    {family: "3des", name: "3DES", mode: "", primitive: "block-cipher", keySize: 168},
	"des-ede3-cbc": {family: "3des", name: "3DES-CBC", mode: "cbc", primitive: "block-cipher", keySize: 168},
	"rc4":         {family: "rc4", name: "RC4", mode: "", primitive: "stream-cipher", keySize: 0},
}

func (s *JSScanner) detectNodeCrypto(root *sitter.Node, path string, content []byte, cp *ConstPropagator, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match method calls: X.methodName(args)
	// This catches crypto.createHash(...), crypto.createCipheriv(...), etc.
	queryStr := `(call_expression
		function: (member_expression
			object: (identifier) @obj
			property: (property_identifier) @method)
		arguments: (arguments) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var objNode, methodNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				objNode = capture.Node
			case 1:
				methodNode = capture.Node
			case 2:
				argsNode = capture.Node
			}
		}
		if objNode == nil || methodNode == nil {
			continue
		}

		objName := scanner.NodeText(objNode, content)
		methodName := scanner.NodeText(methodNode, content)

		// Only process calls on "crypto" (or whatever alias we could track)
		if objName != "crypto" {
			continue
		}

		callNode := getCallNode(methodNode)

		switch methodName {
		case "createHash":
			finding := s.handleCreateHash(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "createHmac":
			finding := s.handleCreateHmac(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "createCipher", "createCipheriv", "createDecipher", "createDecipheriv":
			finding := s.handleCreateCipher(callNode, argsNode, path, content, cp, methodName)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "generateKeyPairSync", "generateKeyPair":
			finding := s.handleGenerateKeyPair(callNode, argsNode, path, content, cp, methodName)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "createDiffieHellman":
			finding := s.handleDiffieHellman(callNode, path, content)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "createECDH":
			finding := s.handleECDH(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "pbkdf2", "pbkdf2Sync":
			finding := s.handlePBKDF2(callNode, argsNode, path, content, cp, methodName)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "scrypt", "scryptSync":
			finding := s.handleScrypt(callNode, path, content, methodName)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

func (s *JSScanner) handleCreateHash(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	normalized := strings.ToLower(algoStr)
	info, ok := hashAlgorithms[normalized]
	if !ok {
		// Unrecognized hash, still report
		info = struct {
			family string
			name   string
		}{family: normalized, name: strings.ToUpper(algoStr)}
	}

	qi := quantum.GetInfo(info.family)
	severity := hashSeverity(info.family)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       info.name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "hash",
			AlgorithmFamily:  info.family,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"digest"},
		},
		Description: fmt.Sprintf("Hash function %s via crypto.createHash()", info.name),
		RuleID:      fmt.Sprintf("cbom-js-crypto-createHash-%s", normalized),
		Pass:        1,
	}
}

func (s *JSScanner) handleCreateHmac(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	hashAlgo, confidence := resolveFirstArg(argsNode, content, cp)
	if hashAlgo == "" {
		hashAlgo = "unknown"
		confidence = types.ConfidenceLow
	}

	normalized := strings.ToLower(hashAlgo)
	info, ok := hashAlgorithms[normalized]
	if !ok {
		info = struct {
			family string
			name   string
		}{family: normalized, name: strings.ToUpper(hashAlgo)}
	}

	name := fmt.Sprintf("HMAC-%s", info.name)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:       "mac",
			AlgorithmFamily: "hmac",
			CryptoFunctions: []string{"mac"},
		},
		Description: fmt.Sprintf("HMAC with %s via crypto.createHmac()", info.name),
		RuleID:      fmt.Sprintf("cbom-js-crypto-createHmac-%s", normalized),
		Pass:        1,
	}
}

func (s *JSScanner) handleCreateCipher(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator, methodName string) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	normalized := strings.ToLower(algoStr)
	info, ok := cipherAlgorithms[normalized]
	if !ok {
		// Unrecognized cipher, still report
		info = struct {
			family    string
			name      string
			mode      string
			primitive string
			keySize   int
		}{family: normalized, name: strings.ToUpper(algoStr), primitive: "block-cipher"}
	}

	qi := quantum.GetInfo(info.family)
	severity := cipherSeverity(info.family, info.mode)

	cryptoFn := "encrypt"
	if strings.Contains(methodName, "Decipher") {
		cryptoFn = "decrypt"
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       info.name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        info.primitive,
			AlgorithmFamily:  info.family,
			Mode:             info.mode,
			KeySize:          info.keySize,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{cryptoFn},
		},
		Description: fmt.Sprintf("Cipher %s via crypto.%s()", info.name, methodName),
		RuleID:      fmt.Sprintf("cbom-js-crypto-%s-%s", methodName, normalized),
		Pass:        1,
	}
}

func (s *JSScanner) handleGenerateKeyPair(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator, methodName string) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	normalized := strings.ToLower(algoStr)

	// Try to extract modulusLength from the options object (2nd argument)
	keySize := resolveObjectPropertyInt(argsNode, 1, "modulusLength", content, cp)

	qi := quantum.GetInfo(normalized)
	severity := types.SeverityInfo
	if normalized == "rsa" && keySize > 0 && keySize < 2048 {
		severity = types.SeverityHigh
	}

	name := strings.ToUpper(algoStr)
	if keySize > 0 {
		name = fmt.Sprintf("%s-%d", strings.ToUpper(algoStr), keySize)
	}

	primitive := "pke"
	if normalized == "ec" || normalized == "ed25519" || normalized == "ed448" || normalized == "x25519" || normalized == "x448" {
		primitive = "key-agree"
	} else if normalized == "dsa" {
		primitive = "signature"
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        primitive,
			AlgorithmFamily:  normalized,
			KeySize:          keySize,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: fmt.Sprintf("%s key generation via crypto.%s()", name, methodName),
		RuleID:      fmt.Sprintf("cbom-js-crypto-%s-%s", methodName, normalized),
		Pass:        1,
	}
}

func (s *JSScanner) handleDiffieHellman(callNode *sitter.Node, path string, content []byte) *types.Finding {
	qi := quantum.GetInfo("dh")

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       "DH",
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			Primitive:        "key-agree",
			AlgorithmFamily:  "dh",
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: "Diffie-Hellman key exchange via crypto.createDiffieHellman()",
		RuleID:      "cbom-js-crypto-createDiffieHellman",
		Pass:        1,
	}
}

func (s *JSScanner) handleECDH(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	curveName, confidence := resolveFirstArg(argsNode, content, cp)
	if curveName == "" {
		curveName = "unknown"
		confidence = types.ConfidenceLow
	}

	qi := quantum.GetInfo("ecdh")
	name := "ECDH"
	if curveName != "unknown" {
		name = fmt.Sprintf("ECDH-%s", curveName)
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "key-agree",
			AlgorithmFamily:  "ecdh",
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: fmt.Sprintf("ECDH key agreement (%s) via crypto.createECDH()", curveName),
		RuleID:      "cbom-js-crypto-createECDH",
		Pass:        1,
	}
}

func (s *JSScanner) handlePBKDF2(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator, methodName string) *types.Finding {
	// pbkdf2(password, salt, iterations, keylen, digest, callback)
	// pbkdf2Sync(password, salt, iterations, keylen, digest)
	// The digest is the 5th arg (index 4)
	hashAlgo := "unknown"
	confidence := types.ConfidenceLow

	if argsNode != nil {
		hashAlgo, confidence = resolveNthArg(argsNode, 4, content, cp)
		if hashAlgo == "" {
			hashAlgo = "unknown"
			confidence = types.ConfidenceLow
		}
	}

	name := fmt.Sprintf("PBKDF2-%s", strings.ToUpper(hashAlgo))

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:       "kdf",
			AlgorithmFamily: "pbkdf2",
			CryptoFunctions: []string{"derive"},
		},
		Description: fmt.Sprintf("Key derivation PBKDF2 via crypto.%s()", methodName),
		RuleID:      fmt.Sprintf("cbom-js-crypto-%s", methodName),
		Pass:        1,
	}
}

func (s *JSScanner) handleScrypt(callNode *sitter.Node, path string, content []byte, methodName string) *types.Finding {
	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       "Scrypt",
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			Primitive:       "kdf",
			AlgorithmFamily: "scrypt",
			CryptoFunctions: []string{"derive"},
		},
		Description: fmt.Sprintf("Key derivation Scrypt via crypto.%s()", methodName),
		RuleID:      fmt.Sprintf("cbom-js-crypto-%s", methodName),
		Pass:        1,
	}
}

// ---------------------------------------------------------------------------
// jsonwebtoken detection
// ---------------------------------------------------------------------------

func (s *JSScanner) detectJWT(root *sitter.Node, path string, content []byte, cp *ConstPropagator, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match: jwt.sign(payload, secret, options) and jwt.verify(token, secret, options)
	queryStr := `(call_expression
		function: (member_expression
			object: (identifier) @obj
			property: (property_identifier) @method)
		arguments: (arguments) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var objNode, methodNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				objNode = capture.Node
			case 1:
				methodNode = capture.Node
			case 2:
				argsNode = capture.Node
			}
		}
		if objNode == nil || methodNode == nil {
			continue
		}

		objName := scanner.NodeText(objNode, content)
		methodName := scanner.NodeText(methodNode, content)

		if objName != "jwt" {
			continue
		}

		callNode := getCallNode(methodNode)

		switch methodName {
		case "sign":
			jwtFindings := s.handleJWTSign(callNode, argsNode, path, content, cp)
			findings = append(findings, jwtFindings...)
		case "verify":
			jwtFindings := s.handleJWTVerify(callNode, argsNode, path, content, cp)
			findings = append(findings, jwtFindings...)
		}
	}

	return findings
}

func (s *JSScanner) handleJWTSign(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	if argsNode == nil {
		return nil
	}

	// jwt.sign(payload, secret, { algorithm: 'HS256' })
	// The algorithm is in the options object (3rd arg, index 2)
	algo := extractAlgorithmFromOptionsArg(argsNode, 2, content, cp)
	if algo == "" {
		return nil
	}

	return s.createJWTFindings(callNode, path, content, []string{algo}, "sign")
}

func (s *JSScanner) handleJWTVerify(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	if argsNode == nil {
		return nil
	}

	// jwt.verify(token, secret, { algorithms: ['HS256', 'HS384'] })
	// The algorithms array is in the options object (3rd arg, index 2)
	algos := extractAlgorithmsArrayFromOptionsArg(argsNode, 2, content, cp)
	if len(algos) == 0 {
		return nil
	}

	return s.createJWTFindings(callNode, path, content, algos, "verify")
}

func (s *JSScanner) createJWTFindings(callNode *sitter.Node, path string, content []byte, algos []string, operation string) []types.Finding {
	var findings []types.Finding

	for _, algo := range algos {
		normalized := strings.ToLower(algo)
		severity := types.SeverityInfo
		name := strings.ToUpper(algo)

		// alg:none is critical
		if normalized == "none" {
			severity = types.SeverityCritical
			name = "none (unsigned)"
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "mac",
				AlgorithmFamily: "jwt",
				CryptoFunctions: []string{operation},
			},
			Description: fmt.Sprintf("JWT %s with algorithm %s via jsonwebtoken", operation, name),
			RuleID:      fmt.Sprintf("cbom-js-jwt-%s-%s", operation, normalized),
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// node-forge detection
// ---------------------------------------------------------------------------

func (s *JSScanner) detectForge(root *sitter.Node, path string, content []byte, cp *ConstPropagator, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Detect forge.md.XXX.create() for hash functions
	findings = append(findings, s.detectForgeHash(root, path, content, lang)...)

	// Detect forge.cipher.createCipher(algo, key)
	findings = append(findings, s.detectForgeCipher(root, path, content, cp, lang)...)

	// Detect forge.pki.rsa.generateKeyPair(options)
	findings = append(findings, s.detectForgeRSA(root, path, content, cp, lang)...)

	// Detect forge.hmac.create()
	findings = append(findings, s.detectForgeHMAC(root, path, content, lang)...)

	return findings
}

// forgeHashAlgorithms maps forge.md.XXX identifiers to algorithm info.
var forgeHashAlgorithms = map[string]struct {
	family string
	name   string
}{
	"md5":    {family: "md5", name: "MD5"},
	"sha1":   {family: "sha1", name: "SHA-1"},
	"sha256": {family: "sha-256", name: "SHA-256"},
	"sha384": {family: "sha-384", name: "SHA-384"},
	"sha512": {family: "sha-512", name: "SHA-512"},
}

func (s *JSScanner) detectForgeHash(root *sitter.Node, path string, content []byte, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match forge.md.XXX.create() — the pattern is a chain: forge.md.sha256.create()
	// tree-sitter sees this as nested member_expressions.
	// We look for call_expression where function is a member_expression chain ending in .create()
	// and the chain contains "forge" at the root and "md" as second part.
	queryStr := `(call_expression
		function: (member_expression
			object: (member_expression
				object: (member_expression
					object: (identifier) @root_obj
					property: (property_identifier) @ns)
				property: (property_identifier) @algo)
			property: (property_identifier) @method)
		(#eq? @method "create"))`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var rootObjNode, nsNode, algoNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				rootObjNode = capture.Node
			case 1:
				nsNode = capture.Node
			case 2:
				algoNode = capture.Node
			}
		}
		if rootObjNode == nil || nsNode == nil || algoNode == nil {
			continue
		}

		if scanner.NodeText(rootObjNode, content) != "forge" {
			continue
		}
		if scanner.NodeText(nsNode, content) != "md" {
			continue
		}

		algoName := scanner.NodeText(algoNode, content)
		info, ok := forgeHashAlgorithms[algoName]
		if !ok {
			continue
		}

		callNode := getCallNodeFromChild(algoNode, 4)
		qi := quantum.GetInfo(info.family)
		severity := hashSeverity(info.family)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       info.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "hash",
				AlgorithmFamily:  info.family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"digest"},
			},
			Description: fmt.Sprintf("Hash function %s via forge.md.%s.create()", info.name, algoName),
			RuleID:      fmt.Sprintf("cbom-js-forge-md-%s", algoName),
			Pass:        1,
		})
	}

	return findings
}

// forgeCipherAlgorithms maps forge cipher strings to algorithm info.
var forgeCipherAlgorithms = map[string]struct {
	family    string
	name      string
	mode      string
	primitive string
}{
	"aes-cbc":     {family: "aes", name: "AES-CBC", mode: "cbc", primitive: "block-cipher"},
	"aes-gcm":     {family: "aes", name: "AES-GCM", mode: "gcm", primitive: "ae"},
	"aes-ecb":     {family: "aes", name: "AES-ECB", mode: "ecb", primitive: "block-cipher"},
	"aes-ctr":     {family: "aes", name: "AES-CTR", mode: "ctr", primitive: "block-cipher"},
	"des-cbc":     {family: "des", name: "DES-CBC", mode: "cbc", primitive: "block-cipher"},
	"des-ecb":     {family: "des", name: "DES-ECB", mode: "ecb", primitive: "block-cipher"},
	"3des-cbc":    {family: "3des", name: "3DES-CBC", mode: "cbc", primitive: "block-cipher"},
	"3des-ecb":    {family: "3des", name: "3DES-ECB", mode: "ecb", primitive: "block-cipher"},
	"rc4":         {family: "rc4", name: "RC4", mode: "", primitive: "stream-cipher"},
}

func (s *JSScanner) detectForgeCipher(root *sitter.Node, path string, content []byte, cp *ConstPropagator, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match: forge.cipher.createCipher(algo, key)
	queryStr := `(call_expression
		function: (member_expression
			object: (member_expression
				object: (identifier) @root_obj
				property: (property_identifier) @ns)
			property: (property_identifier) @method)
		arguments: (arguments) @args
		(#eq? @method "createCipher"))`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var rootObjNode, nsNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				rootObjNode = capture.Node
			case 1:
				nsNode = capture.Node
			case 3:
				argsNode = capture.Node
			}
		}
		if rootObjNode == nil || nsNode == nil || argsNode == nil {
			continue
		}

		if scanner.NodeText(rootObjNode, content) != "forge" {
			continue
		}
		if scanner.NodeText(nsNode, content) != "cipher" {
			continue
		}

		algoStr, confidence := resolveFirstArg(argsNode, content, cp)
		if algoStr == "" {
			continue
		}

		normalized := strings.ToLower(algoStr)
		info, ok := forgeCipherAlgorithms[normalized]
		if !ok {
			// Unrecognized cipher, still report
			info = struct {
				family    string
				name      string
				mode      string
				primitive string
			}{family: normalized, name: strings.ToUpper(algoStr), primitive: "block-cipher"}
		}

		callNode := getCallNodeFromChild(nsNode, 4)
		qi := quantum.GetInfo(info.family)
		severity := cipherSeverity(info.family, info.mode)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       info.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: confidence,
			Properties: types.CryptoProperties{
				Primitive:        info.primitive,
				AlgorithmFamily:  info.family,
				Mode:             info.mode,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt"},
			},
			Description: fmt.Sprintf("Cipher %s via forge.cipher.createCipher()", info.name),
			RuleID:      fmt.Sprintf("cbom-js-forge-cipher-%s", normalized),
			Pass:        1,
		})
	}

	return findings
}

func (s *JSScanner) detectForgeRSA(root *sitter.Node, path string, content []byte, cp *ConstPropagator, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match: forge.pki.rsa.generateKeyPair(options)
	// This is a deeply nested member expression chain.
	queryStr := `(call_expression
		function: (member_expression
			object: (member_expression
				object: (member_expression
					object: (identifier) @root_obj
					property: (property_identifier) @ns1)
				property: (property_identifier) @ns2)
			property: (property_identifier) @method)
		arguments: (arguments) @args
		(#eq? @method "generateKeyPair"))`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var rootObjNode, ns1Node, ns2Node, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				rootObjNode = capture.Node
			case 1:
				ns1Node = capture.Node
			case 2:
				ns2Node = capture.Node
			case 4:
				argsNode = capture.Node
			}
		}
		if rootObjNode == nil || ns1Node == nil || ns2Node == nil {
			continue
		}

		if scanner.NodeText(rootObjNode, content) != "forge" {
			continue
		}
		if scanner.NodeText(ns1Node, content) != "pki" {
			continue
		}
		if scanner.NodeText(ns2Node, content) != "rsa" {
			continue
		}

		// Try to extract bits from options object argument
		keySize := 0
		if argsNode != nil {
			keySize = resolveObjectPropertyInt(argsNode, 0, "bits", content, cp)
		}

		qi := quantum.GetInfo("rsa")
		severity := types.SeverityInfo
		if keySize > 0 && keySize < 2048 {
			severity = types.SeverityHigh
		}

		name := "RSA"
		if keySize > 0 {
			name = fmt.Sprintf("RSA-%d", keySize)
		}

		callNode := getCallNodeFromChild(ns2Node, 5)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "pke",
				AlgorithmFamily:  "rsa",
				KeySize:          keySize,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"generate"},
			},
			Description: fmt.Sprintf("RSA key generation (bits=%d) via forge.pki.rsa.generateKeyPair()", keySize),
			RuleID:      "cbom-js-forge-rsa-generateKeyPair",
			Pass:        1,
		})
	}

	return findings
}

func (s *JSScanner) detectForgeHMAC(root *sitter.Node, path string, content []byte, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match: forge.hmac.create()
	queryStr := `(call_expression
		function: (member_expression
			object: (member_expression
				object: (identifier) @root_obj
				property: (property_identifier) @ns)
			property: (property_identifier) @method)
		(#eq? @method "create"))`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var rootObjNode, nsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				rootObjNode = capture.Node
			case 1:
				nsNode = capture.Node
			}
		}
		if rootObjNode == nil || nsNode == nil {
			continue
		}

		if scanner.NodeText(rootObjNode, content) != "forge" {
			continue
		}
		if scanner.NodeText(nsNode, content) != "hmac" {
			continue
		}

		callNode := getCallNodeFromChild(nsNode, 4)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "HMAC",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "mac",
				AlgorithmFamily: "hmac",
				CryptoFunctions: []string{"mac"},
			},
			Description: "HMAC via forge.hmac.create()",
			RuleID:      "cbom-js-forge-hmac-create",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Web Crypto API detection
// ---------------------------------------------------------------------------

func (s *JSScanner) detectWebCrypto(root *sitter.Node, path string, content []byte, cp *ConstPropagator, lang *sitter.Language) []types.Finding {
	var findings []types.Finding

	// Match: crypto.subtle.encrypt/decrypt/digest/generateKey/sign/verify(...)
	queryStr := `(call_expression
		function: (member_expression
			object: (member_expression
				object: (identifier) @root_obj
				property: (property_identifier) @ns)
			property: (property_identifier) @method)
		arguments: (arguments) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var rootObjNode, nsNode, methodNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				rootObjNode = capture.Node
			case 1:
				nsNode = capture.Node
			case 2:
				methodNode = capture.Node
			case 3:
				argsNode = capture.Node
			}
		}
		if rootObjNode == nil || nsNode == nil || methodNode == nil {
			continue
		}

		if scanner.NodeText(rootObjNode, content) != "crypto" {
			continue
		}
		if scanner.NodeText(nsNode, content) != "subtle" {
			continue
		}

		methodName := scanner.NodeText(methodNode, content)
		callNode := getCallNodeFromChild(methodNode, 3)

		switch methodName {
		case "encrypt", "decrypt":
			finding := s.handleWebCryptoEncrypt(callNode, argsNode, path, content, cp, methodName)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "digest":
			finding := s.handleWebCryptoDigest(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "generateKey":
			finding := s.handleWebCryptoGenerateKey(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

// webCryptoAlgorithms maps Web Crypto algorithm name strings to families.
var webCryptoAlgorithms = map[string]struct {
	family    string
	name      string
	primitive string
	mode      string
}{
	"aes-gcm": {family: "aes", name: "AES-GCM", primitive: "ae", mode: "gcm"},
	"aes-cbc": {family: "aes", name: "AES-CBC", primitive: "block-cipher", mode: "cbc"},
	"aes-ctr": {family: "aes", name: "AES-CTR", primitive: "block-cipher", mode: "ctr"},
	"rsa-oaep": {family: "rsa", name: "RSA-OAEP", primitive: "pke"},
	"rsa-pss":  {family: "rsa", name: "RSA-PSS", primitive: "signature"},
	"ecdsa":    {family: "ecdsa", name: "ECDSA", primitive: "signature"},
	"ecdh":     {family: "ecdh", name: "ECDH", primitive: "key-agree"},
}

func (s *JSScanner) handleWebCryptoEncrypt(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator, methodName string) *types.Finding {
	if argsNode == nil {
		return nil
	}

	// First arg is an algorithm object or string: { name: 'AES-GCM' } or 'AES-GCM'
	algoName := extractNameFromFirstObjectArg(argsNode, content, cp)
	if algoName == "" {
		return nil
	}

	normalized := strings.ToLower(algoName)
	info, ok := webCryptoAlgorithms[normalized]
	if !ok {
		info = struct {
			family    string
			name      string
			primitive string
			mode      string
		}{family: normalized, name: strings.ToUpper(algoName), primitive: "block-cipher"}
	}

	qi := quantum.GetInfo(info.family)
	severity := cipherSeverity(info.family, info.mode)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       info.name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			Primitive:        info.primitive,
			AlgorithmFamily:  info.family,
			Mode:             info.mode,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{methodName},
		},
		Description: fmt.Sprintf("Web Crypto %s with %s", methodName, info.name),
		RuleID:      fmt.Sprintf("cbom-js-webcrypto-%s-%s", methodName, normalized),
		Pass:        1,
	}
}

// webCryptoHashAlgorithms maps Web Crypto digest strings to info.
var webCryptoHashAlgorithms = map[string]struct {
	family string
	name   string
}{
	"sha-1":   {family: "sha1", name: "SHA-1"},
	"sha-256": {family: "sha-256", name: "SHA-256"},
	"sha-384": {family: "sha-384", name: "SHA-384"},
	"sha-512": {family: "sha-512", name: "SHA-512"},
}

func (s *JSScanner) handleWebCryptoDigest(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	// First arg is a string or object: 'SHA-256' or { name: 'SHA-256' }
	algoName, confidence := resolveFirstArg(argsNode, content, cp)
	if algoName == "" {
		// Try extracting from object
		algoName = extractNameFromFirstObjectArg(argsNode, content, cp)
		if algoName != "" {
			confidence = types.ConfidenceHigh
		}
	}
	if algoName == "" {
		return nil
	}

	normalized := strings.ToLower(algoName)
	info, ok := webCryptoHashAlgorithms[normalized]
	if !ok {
		info = struct {
			family string
			name   string
		}{family: normalized, name: strings.ToUpper(algoName)}
	}

	qi := quantum.GetInfo(info.family)
	severity := hashSeverity(info.family)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       info.name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "hash",
			AlgorithmFamily:  info.family,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"digest"},
		},
		Description: fmt.Sprintf("Web Crypto digest with %s", info.name),
		RuleID:      fmt.Sprintf("cbom-js-webcrypto-digest-%s", normalized),
		Pass:        1,
	}
}

func (s *JSScanner) handleWebCryptoGenerateKey(callNode *sitter.Node, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	algoName := extractNameFromFirstObjectArg(argsNode, content, cp)
	if algoName == "" {
		return nil
	}

	normalized := strings.ToLower(algoName)
	info, ok := webCryptoAlgorithms[normalized]
	if !ok {
		info = struct {
			family    string
			name      string
			primitive string
			mode      string
		}{family: normalized, name: strings.ToUpper(algoName), primitive: "pke"}
	}

	// Try to extract modulusLength or length from the object
	keySize := extractIntPropertyFromFirstObjectArg(argsNode, "modulusLength", content)
	if keySize == 0 {
		keySize = extractIntPropertyFromFirstObjectArg(argsNode, "length", content)
	}

	qi := quantum.GetInfo(info.family)
	severity := types.SeverityInfo
	if info.family == "rsa" && keySize > 0 && keySize < 2048 {
		severity = types.SeverityHigh
	}

	name := info.name
	if keySize > 0 {
		name = fmt.Sprintf("%s-%d", info.name, keySize)
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			Primitive:        info.primitive,
			AlgorithmFamily:  info.family,
			Mode:             info.mode,
			KeySize:          keySize,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: fmt.Sprintf("Web Crypto generateKey with %s", name),
		RuleID:      fmt.Sprintf("cbom-js-webcrypto-generateKey-%s", normalized),
		Pass:        1,
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// getCallNode walks up from a method property node to find the enclosing call_expression.
func getCallNode(node *sitter.Node) *sitter.Node {
	// property -> member_expression -> call_expression
	n := node.Parent() // member_expression
	if n != nil {
		n = n.Parent() // call_expression
	}
	if n == nil {
		return node
	}
	return n
}

// getCallNodeFromChild walks up from a deeply nested node to find the enclosing call_expression.
func getCallNodeFromChild(node *sitter.Node, maxDepth int) *sitter.Node {
	n := node
	for i := 0; i < maxDepth && n != nil; i++ {
		if n.Type() == "call_expression" {
			return n
		}
		n = n.Parent()
	}
	if n == nil {
		return node
	}
	return n
}

// resolveFirstArg extracts the first positional argument value from an arguments node.
// Returns the resolved value and the confidence level.
func resolveFirstArg(argsNode *sitter.Node, content []byte, cp *ConstPropagator) (string, types.Confidence) {
	return resolveNthArg(argsNode, 0, content, cp)
}

// resolveNthArg extracts the nth positional argument (0-indexed) from an arguments node.
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
			case "string":
				return unquoteJSString(child.Content(content)), types.ConfidenceHigh
			case "template_string":
				raw := child.Content(content)
				if len(raw) >= 2 && raw[0] == '`' && raw[len(raw)-1] == '`' {
					inner := raw[1 : len(raw)-1]
					if !strings.Contains(inner, "${") {
						return inner, types.ConfidenceHigh
					}
				}
				return "", types.ConfidenceLow
			case "number":
				return child.Content(content), types.ConfidenceHigh
			case "identifier":
				name := child.Content(content)
				if val, ok := cp.Resolve(name); ok {
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

// resolveObjectPropertyInt extracts an integer property from an object literal
// at position argIndex in the arguments.
func resolveObjectPropertyInt(argsNode *sitter.Node, argIndex int, propName string, content []byte, cp *ConstPropagator) int {
	if argsNode == nil {
		return 0
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

		if posIdx == argIndex {
			if child.Type() == "object" {
				return extractIntPropertyFromObject(child, propName, content, cp)
			}
			return 0
		}
		posIdx++
	}

	return 0
}

// extractIntPropertyFromObject extracts an integer property from an object literal node.
func extractIntPropertyFromObject(objNode *sitter.Node, propName string, content []byte, cp *ConstPropagator) int {
	for i := 0; i < int(objNode.ChildCount()); i++ {
		child := objNode.Child(i)
		if child == nil || child.Type() != "pair" {
			continue
		}

		keyNode := child.ChildByFieldName("key")
		valueNode := child.ChildByFieldName("value")
		if keyNode == nil || valueNode == nil {
			continue
		}

		keyText := ""
		switch keyNode.Type() {
		case "property_identifier":
			keyText = keyNode.Content(content)
		case "string":
			keyText = unquoteJSString(keyNode.Content(content))
		}

		if keyText != propName {
			continue
		}

		switch valueNode.Type() {
		case "number":
			val, err := strconv.Atoi(valueNode.Content(content))
			if err == nil {
				return val
			}
		case "identifier":
			name := valueNode.Content(content)
			if resolved, ok := cp.Resolve(name); ok {
				val, err := strconv.Atoi(resolved)
				if err == nil {
					return val
				}
			}
		}
	}

	return 0
}

// extractStringPropertyFromObject extracts a string property from an object literal node.
func extractStringPropertyFromObject(objNode *sitter.Node, propName string, content []byte, cp *ConstPropagator) string {
	for i := 0; i < int(objNode.ChildCount()); i++ {
		child := objNode.Child(i)
		if child == nil || child.Type() != "pair" {
			continue
		}

		keyNode := child.ChildByFieldName("key")
		valueNode := child.ChildByFieldName("value")
		if keyNode == nil || valueNode == nil {
			continue
		}

		keyText := ""
		switch keyNode.Type() {
		case "property_identifier":
			keyText = keyNode.Content(content)
		case "string":
			keyText = unquoteJSString(keyNode.Content(content))
		}

		if keyText != propName {
			continue
		}

		switch valueNode.Type() {
		case "string":
			return unquoteJSString(valueNode.Content(content))
		case "template_string":
			raw := valueNode.Content(content)
			if len(raw) >= 2 && raw[0] == '`' && raw[len(raw)-1] == '`' {
				inner := raw[1 : len(raw)-1]
				if !strings.Contains(inner, "${") {
					return inner
				}
			}
		case "identifier":
			name := valueNode.Content(content)
			if val, ok := cp.Resolve(name); ok {
				return val
			}
		}
	}

	return ""
}

// extractAlgorithmFromOptionsArg extracts the "algorithm" property from an
// options object at the given argument index.
func extractAlgorithmFromOptionsArg(argsNode *sitter.Node, argIndex int, content []byte, cp *ConstPropagator) string {
	if argsNode == nil {
		return ""
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

		if posIdx == argIndex {
			if child.Type() == "object" {
				return extractStringPropertyFromObject(child, "algorithm", content, cp)
			}
			return ""
		}
		posIdx++
	}

	return ""
}

// extractAlgorithmsArrayFromOptionsArg extracts the "algorithms" array property
// from an options object at the given argument index.
func extractAlgorithmsArrayFromOptionsArg(argsNode *sitter.Node, argIndex int, content []byte, cp *ConstPropagator) []string {
	if argsNode == nil {
		return nil
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

		if posIdx == argIndex {
			if child.Type() == "object" {
				return extractStringArrayPropertyFromObject(child, "algorithms", content)
			}
			return nil
		}
		posIdx++
	}

	return nil
}

// extractStringArrayPropertyFromObject extracts a string array property from an object.
func extractStringArrayPropertyFromObject(objNode *sitter.Node, propName string, content []byte) []string {
	for i := 0; i < int(objNode.ChildCount()); i++ {
		child := objNode.Child(i)
		if child == nil || child.Type() != "pair" {
			continue
		}

		keyNode := child.ChildByFieldName("key")
		valueNode := child.ChildByFieldName("value")
		if keyNode == nil || valueNode == nil {
			continue
		}

		keyText := ""
		switch keyNode.Type() {
		case "property_identifier":
			keyText = keyNode.Content(content)
		case "string":
			keyText = unquoteJSString(keyNode.Content(content))
		}

		if keyText != propName {
			continue
		}

		if valueNode.Type() == "array" {
			return extractStringsFromArray(valueNode, content)
		}
	}

	return nil
}

// extractStringsFromArray extracts string values from an array literal node.
func extractStringsFromArray(arrayNode *sitter.Node, content []byte) []string {
	var result []string
	for i := 0; i < int(arrayNode.ChildCount()); i++ {
		child := arrayNode.Child(i)
		if child == nil {
			continue
		}
		if child.Type() == "string" {
			result = append(result, unquoteJSString(child.Content(content)))
		}
	}
	return result
}

// extractNameFromFirstObjectArg extracts the "name" property from the first
// argument if it's an object literal, e.g. { name: 'AES-GCM' }.
func extractNameFromFirstObjectArg(argsNode *sitter.Node, content []byte, cp *ConstPropagator) string {
	if argsNode == nil {
		return ""
	}

	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}
		nodeType := child.Type()
		if nodeType == "(" || nodeType == ")" || nodeType == "," {
			continue
		}
		// First non-punctuation child
		if child.Type() == "object" {
			return extractStringPropertyFromObject(child, "name", content, cp)
		}
		return ""
	}

	return ""
}

// extractIntPropertyFromFirstObjectArg extracts an integer property from the
// first argument if it's an object literal.
func extractIntPropertyFromFirstObjectArg(argsNode *sitter.Node, propName string, content []byte) int {
	if argsNode == nil {
		return 0
	}

	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}
		nodeType := child.Type()
		if nodeType == "(" || nodeType == ")" || nodeType == "," {
			continue
		}
		if child.Type() == "object" {
			return extractIntPropertyFromObject(child, propName, content, nil)
		}
		return 0
	}

	return 0
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
