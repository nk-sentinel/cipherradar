// Package kotlin detects cryptographic API usage in Kotlin source files.
//
// Kotlin uses the same JCA/JCE and Bouncy Castle APIs as Java since it runs
// on the JVM. Because there is no Go binding for a tree-sitter Kotlin grammar
// in github.com/smacker/go-tree-sitter, this scanner uses the Java grammar as
// a fallback. Crypto API calls like Cipher.getInstance("AES") produce
// identical AST structure under the Java grammar because Kotlin expression
// syntax for these method calls is the same as Java's. The main difference
// (val/var declarations vs typed declarations) is handled by the constant
// propagation module which walks Kotlin-compatible AST nodes.
package kotlin

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	javaLang "github.com/smacker/go-tree-sitter/java"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kdf"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// KotlinScanner detects cryptographic API usage in Kotlin source files.
// It uses the Java tree-sitter grammar because Kotlin crypto API calls
// (JCA/JCE, Bouncy Castle) use identical syntax to Java and produce
// compatible AST nodes.
type KotlinScanner struct {
	lang *sitter.Language
}

// New creates a new KotlinScanner instance.
func New() *KotlinScanner {
	return &KotlinScanner{
		lang: javaLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *KotlinScanner) Name() string {
	return "kotlin"
}

// Extensions returns the file extensions this scanner handles.
func (s *KotlinScanner) Extensions() []string {
	return []string{".kt", ".kts"}
}

// ScanFile scans a single Kotlin file's content and returns cryptographic findings.
func (s *KotlinScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
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

	// Detect JCA/JCE usage (Cipher.getInstance, MessageDigest.getInstance, etc.)
	jcaFindings := s.detectJCA(root, path, content, cp)
	findings = append(findings, jcaFindings...)

	// Detect Bouncy Castle usage
	bcFindings := s.detectBouncyCastle(root, path, content, cp)
	findings = append(findings, bcFindings...)

	// Detect SSL/TLS usage
	sslFindings := s.detectSSL(root, path, content, cp)
	findings = append(findings, sslFindings...)

	// Detect PBEKeySpec (PBKDF2 with iteration count checking)
	pbeFindings := s.detectPBEKeySpec(root, path, content, cp)
	findings = append(findings, pbeFindings...)

	return scanner.AnnotateFindings(findings), nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// JCA algorithm string parser
// ---------------------------------------------------------------------------

// JCAAlgorithm represents a parsed JCA algorithm specification string.
type JCAAlgorithm struct {
	Algorithm string // e.g. "AES"
	Mode      string // e.g. "CBC"
	Padding   string // e.g. "PKCS5Padding"
}

// ParseJCAAlgorithm parses a JCA algorithm string like "AES/CBC/PKCS5Padding"
// into its components.
func ParseJCAAlgorithm(spec string) JCAAlgorithm {
	parts := strings.Split(spec, "/")
	result := JCAAlgorithm{
		Algorithm: parts[0],
	}
	if len(parts) > 1 {
		result.Mode = parts[1]
	}
	if len(parts) > 2 {
		result.Padding = parts[2]
	}
	return result
}

// ParseSignatureAlgorithm parses a JCA signature algorithm string like "SHA256withRSA"
// into hash and key algorithm components.
func ParseSignatureAlgorithm(spec string) (hash string, algo string) {
	lower := strings.ToLower(spec)
	idx := strings.Index(lower, "with")
	if idx < 0 {
		return "", spec
	}
	return spec[:idx], spec[idx+4:]
}

// ---------------------------------------------------------------------------
// JCA/JCE detection
// ---------------------------------------------------------------------------

// jcaClassInfo maps JCA factory classes to detection info.
var jcaClassInfo = map[string]struct {
	primitive string
	ruleTag   string
}{
	"Cipher":           {primitive: "block-cipher", ruleTag: "cipher"},
	"MessageDigest":    {primitive: "hash", ruleTag: "digest"},
	"KeyPairGenerator": {primitive: "pke", ruleTag: "keypairgen"},
	"KeyGenerator":     {primitive: "block-cipher", ruleTag: "keygen"},
	"Mac":              {primitive: "mac", ruleTag: "mac"},
	"Signature":        {primitive: "signature", ruleTag: "signature"},
	"SecretKeySpec":    {primitive: "block-cipher", ruleTag: "secretkeyspec"},
	"SSLContext":       {primitive: "", ruleTag: "sslcontext"},
}

// algorithmFamilyMap maps JCA algorithm names (uppercased) to quantum family names.
var algorithmFamilyMap = map[string]string{
	"AES":        "aes",
	"DES":        "des",
	"DESEDE":     "3des",
	"BLOWFISH":   "blowfish",
	"RC4":        "rc4",
	"ARCFOUR":    "rc4",
	"RSA":        "rsa",
	"DSA":        "dsa",
	"EC":         "ec",
	"ECDSA":      "ecdsa",
	"MD5":        "md5",
	"SHA-1":      "sha1",
	"SHA1":       "sha1",
	"SHA-256":    "sha-256",
	"SHA256":     "sha-256",
	"SHA-384":    "sha-384",
	"SHA384":     "sha-384",
	"SHA-512":    "sha-512",
	"SHA512":     "sha-512",
	"HMACMD5":    "md5",
	"HMACSHA1":   "sha1",
	"HMACSHA256": "sha-256",
	"HMACSHA384": "sha-384",
	"HMACSHA512": "sha-512",
}

// lookupAlgoFamily returns the quantum family key for a given algorithm name.
func lookupAlgoFamily(algo string) string {
	upper := strings.ToUpper(algo)
	if fam, ok := algorithmFamilyMap[upper]; ok {
		return fam
	}
	return strings.ToLower(algo)
}

func (s *KotlinScanner) detectJCA(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for ClassName.getInstance("...") calls
	// Under the Java grammar, Kotlin method calls parse as method_invocation nodes.
	queryStr := `(method_invocation
		object: (identifier) @cls
		name: (identifier) @method
		arguments: (argument_list) @args
		(#eq? @method "getInstance"))`

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

		className := scanner.NodeText(clsNode, content)
		classInfo, known := jcaClassInfo[className]
		if !known {
			continue
		}

		callNode := getCallNode(methodNode)

		switch className {
		case "Cipher":
			finding := s.handleCipherGetInstance(callNode, argsNode, path, content, cp, classInfo)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "MessageDigest":
			finding := s.handleMessageDigestGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "KeyPairGenerator":
			finding := s.handleKeyPairGeneratorGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "KeyGenerator":
			finding := s.handleKeyGeneratorGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "Mac":
			finding := s.handleMacGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "Signature":
			finding := s.handleSignatureGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "SSLContext":
			finding := s.handleSSLContextGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	// Detect SecretKeySpec constructor calls: new SecretKeySpec(bytes, "AES")
	// In Kotlin this is typically SecretKeySpec(bytes, "AES") without "new",
	// but the Java grammar may still parse it. Also detect Java-style "new".
	findings = append(findings, s.detectSecretKeySpec(root, path, content, cp)...)

	return findings
}

func (s *KotlinScanner) handleCipherGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator, classInfo struct {
	primitive string
	ruleTag   string
}) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	parsed := ParseJCAAlgorithm(algoStr)
	algoFamily := lookupAlgoFamily(parsed.Algorithm)
	mode := strings.ToLower(parsed.Mode)

	qi := quantum.GetInfo(algoFamily)
	severity := cipherSeverity(algoFamily, mode)

	// Flag PKCS1v15 padding as MEDIUM severity (padding oracle vulnerability)
	paddingLower := strings.ToLower(parsed.Padding)
	if paddingLower == "pkcs1padding" && strings.ToUpper(parsed.Algorithm) == "RSA" {
		if severity == types.SeverityInfo {
			severity = types.SeverityMedium
		}
	}

	name := buildCipherName(strings.ToUpper(parsed.Algorithm), mode)
	if parsed.Padding != "" {
		name = fmt.Sprintf("%s/%s", name, parsed.Padding)
	}

	ruleID := fmt.Sprintf("cbom-kotlin-jca-cipher-%s", strings.ToLower(parsed.Algorithm))
	if mode != "" {
		ruleID = fmt.Sprintf("%s-%s", ruleID, mode)
	}

	primitive := classInfo.primitive
	if mode == "gcm" {
		primitive = "ae"
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
			AlgorithmFamily:  algoFamily,
			Mode:             mode,
			Padding:          paddingLower,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"encrypt"},
		},
		Description: fmt.Sprintf("Cipher %s via Cipher.getInstance()", algoStr),
		RuleID:      ruleID,
		Pass:        1,
	}
}

func (s *KotlinScanner) handleMessageDigestGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	algoFamily := lookupAlgoFamily(algoStr)
	qi := quantum.GetInfo(algoFamily)
	severity := hashSeverity(algoFamily)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       algoStr,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "hash",
			AlgorithmFamily:  algoFamily,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"digest"},
		},
		Description: fmt.Sprintf("Hash function %s via MessageDigest.getInstance()", algoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-digest-%s", strings.ToLower(strings.ReplaceAll(algoStr, "-", ""))),
		Pass:        1,
	}
}

func (s *KotlinScanner) handleKeyPairGeneratorGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	algoFamily := lookupAlgoFamily(algoStr)
	qi := quantum.GetInfo(algoFamily)

	name := strings.ToUpper(algoStr)
	severity := types.SeverityInfo

	// RSA/DSA/EC are quantum-vulnerable
	if qi.Status == types.QuantumVulnerable {
		severity = types.SeverityInfo
	}

	primitive := "pke"
	if strings.ToUpper(algoStr) == "DSA" || strings.ToUpper(algoStr) == "ECDSA" {
		primitive = "signature"
	} else if strings.ToUpper(algoStr) == "EC" {
		primitive = "pke"
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
			AlgorithmFamily:  algoFamily,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: fmt.Sprintf("Key pair generation using %s via KeyPairGenerator.getInstance()", algoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-keypairgen-%s", strings.ToLower(algoStr)),
		Pass:        1,
	}
}

func (s *KotlinScanner) handleKeyGeneratorGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	algoFamily := lookupAlgoFamily(algoStr)
	qi := quantum.GetInfo(algoFamily)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       strings.ToUpper(algoStr),
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "block-cipher",
			AlgorithmFamily:  algoFamily,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: fmt.Sprintf("Symmetric key generation for %s via KeyGenerator.getInstance()", algoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-keygen-%s", strings.ToLower(algoStr)),
		Pass:        1,
	}
}

func (s *KotlinScanner) handleMacGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	algoFamily := "hmac"
	name := algoStr

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:       "mac",
			AlgorithmFamily: algoFamily,
			CryptoFunctions: []string{"mac"},
		},
		Description: fmt.Sprintf("MAC %s via Mac.getInstance()", algoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-mac-%s", strings.ToLower(algoStr)),
		Pass:        1,
	}
}

func (s *KotlinScanner) handleSignatureGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	hashPart, algoPart := ParseSignatureAlgorithm(algoStr)
	algoFamily := lookupAlgoFamily(algoPart)
	qi := quantum.GetInfo(algoFamily)

	name := algoStr
	if hashPart != "" && algoPart != "" {
		name = fmt.Sprintf("%s with %s", hashPart, algoPart)
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "signature",
			AlgorithmFamily:  algoFamily,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"sign"},
		},
		Description: fmt.Sprintf("Signature %s via Signature.getInstance()", algoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-signature-%s", strings.ToLower(strings.ReplaceAll(algoStr, "/", "-"))),
		Pass:        1,
	}
}

func (s *KotlinScanner) detectSecretKeySpec(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for new SecretKeySpec(bytes, "AES")
	queryStr := `(object_creation_expression
		type: (type_identifier) @cls
		arguments: (argument_list) @args
		(#eq? @cls "SecretKeySpec"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var clsNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0: // @cls
				clsNode = capture.Node
			case 1: // @args
				argsNode = capture.Node
			}
		}
		if clsNode == nil || argsNode == nil {
			continue
		}

		// SecretKeySpec takes (byte[], "algorithm") - algo is 2nd arg
		algoStr, confidence := resolveNthArg(argsNode, 1, content, cp)
		if algoStr == "" {
			continue
		}

		algoFamily := lookupAlgoFamily(algoStr)
		qi := quantum.GetInfo(algoFamily)

		callNode := getObjectCreationNode(clsNode)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetRelatedCryptoMaterial,
			Name:       strings.ToUpper(algoStr) + " key",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: confidence,
			Properties: types.CryptoProperties{
				Primitive:        "block-cipher",
				AlgorithmFamily:  algoFamily,
				MaterialType:     "secret-key",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"generate"},
			},
			Description: fmt.Sprintf("Secret key for %s via SecretKeySpec()", algoStr),
			RuleID:      fmt.Sprintf("cbom-kotlin-jca-secretkeyspec-%s", strings.ToLower(algoStr)),
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Bouncy Castle detection
// ---------------------------------------------------------------------------

// bcEngineAlgorithms maps Bouncy Castle engine class names to algorithm info.
var bcEngineAlgorithms = map[string]struct {
	family    string
	name      string
	primitive string
}{
	"AESEngine":      {family: "aes", name: "AES", primitive: "block-cipher"},
	"DESEngine":      {family: "des", name: "DES", primitive: "block-cipher"},
	"DESedeEngine":   {family: "3des", name: "3DES", primitive: "block-cipher"},
	"BlowfishEngine": {family: "blowfish", name: "Blowfish", primitive: "block-cipher"},
	"RC4Engine":      {family: "rc4", name: "RC4", primitive: "stream-cipher"},
	"RSAEngine":      {family: "rsa", name: "RSA", primitive: "pke"},
	"CamelliaEngine": {family: "camellia", name: "Camellia", primitive: "block-cipher"},
}

// bcModes maps Bouncy Castle mode class names to mode strings.
var bcModes = map[string]string{
	"CBCBlockCipher": "cbc",
	"GCMBlockCipher": "gcm",
	"CFBBlockCipher": "cfb",
	"OFBBlockCipher": "ofb",
	"CTRBlockCipher": "ctr",
	"SICBlockCipher": "ctr",
	"CCMBlockCipher": "ccm",
	"EAXBlockCipher": "eax",
}

// bcDigestAlgorithms maps Bouncy Castle digest class names to algorithm info.
var bcDigestAlgorithms = map[string]struct {
	family string
	name   string
}{
	"SHA256Digest":  {family: "sha-256", name: "SHA-256"},
	"SHA384Digest":  {family: "sha-384", name: "SHA-384"},
	"SHA512Digest":  {family: "sha-512", name: "SHA-512"},
	"SHA1Digest":    {family: "sha1", name: "SHA-1"},
	"MD5Digest":     {family: "md5", name: "MD5"},
	"SHA3Digest":    {family: "sha3-256", name: "SHA3"},
	"BLAKE2bDigest": {family: "blake2b", name: "BLAKE2b"},
	"BLAKE2sDigest": {family: "blake2s", name: "BLAKE2s"},
}

func (s *KotlinScanner) detectBouncyCastle(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for new XxxEngine(), new XxxBlockCipher(...), new XxxDigest()
	queryStr := `(object_creation_expression
		type: (type_identifier) @cls
		arguments: (argument_list) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var clsNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0: // @cls
				clsNode = capture.Node
			case 1: // @args
				argsNode = capture.Node
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
			severity := cipherSeverity(engineInfo.family, "")

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
				Description: fmt.Sprintf("Bouncy Castle %s engine via new %s()", engineInfo.name, className),
				RuleID:      fmt.Sprintf("cbom-kotlin-bc-engine-%s", strings.ToLower(engineInfo.family)),
				Pass:        1,
			})
			continue
		}

		// Check if it's a mode wrapper class (CBCBlockCipher, GCMBlockCipher, etc.)
		if mode, ok := bcModes[className]; ok {
			innerFamily, innerName := extractInnerEngine(argsNode, content)

			qi := quantum.GetInfo(innerFamily)
			severity := cipherSeverity(innerFamily, mode)

			name := innerName
			if mode != "" {
				name = fmt.Sprintf("%s-%s", innerName, strings.ToUpper(mode))
			}

			primitive := "block-cipher"
			if mode == "gcm" || mode == "ccm" || mode == "eax" {
				primitive = "ae"
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   severity,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        primitive,
					AlgorithmFamily:  innerFamily,
					Mode:             mode,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("Bouncy Castle %s in %s mode via new %s()", innerName, strings.ToUpper(mode), className),
				RuleID:      fmt.Sprintf("cbom-kotlin-bc-mode-%s-%s", strings.ToLower(innerFamily), mode),
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
				Description: fmt.Sprintf("Bouncy Castle %s digest via new %s()", digestInfo.name, className),
				RuleID:      fmt.Sprintf("cbom-kotlin-bc-digest-%s", strings.ToLower(digestInfo.family)),
				Pass:        1,
			})
			continue
		}
	}

	return findings
}

// extractInnerEngine tries to find the engine class from the first argument of
// a mode constructor (e.g., new CBCBlockCipher(new AESEngine())).
func extractInnerEngine(argsNode *sitter.Node, content []byte) (family string, name string) {
	if argsNode == nil {
		return "unknown", "Unknown"
	}

	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}
		if child.Type() == "object_creation_expression" {
			typeNode := child.ChildByFieldName("type")
			if typeNode != nil {
				engineName := typeNode.Content(content)
				if info, ok := bcEngineAlgorithms[engineName]; ok {
					return info.family, info.name
				}
			}
		}
	}

	return "unknown", "Unknown"
}

// ---------------------------------------------------------------------------
// SSL/TLS detection
// ---------------------------------------------------------------------------

// sslProtocols maps SSLContext.getInstance() protocol strings to info.
var sslProtocols = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"SSL":     {name: "SSLv3", version: "3.0", severity: types.SeverityHigh},
	"SSLv3":   {name: "SSLv3", version: "3.0", severity: types.SeverityHigh},
	"TLS":     {name: "TLS", version: "", severity: types.SeverityInfo},
	"TLSv1":   {name: "TLSv1.0", version: "1.0", severity: types.SeverityHigh},
	"TLSv1.0": {name: "TLSv1.0", version: "1.0", severity: types.SeverityHigh},
	"TLSv1.1": {name: "TLSv1.1", version: "1.1", severity: types.SeverityHigh},
	"TLSv1.2": {name: "TLSv1.2", version: "1.2", severity: types.SeverityInfo},
	"TLSv1.3": {name: "TLSv1.3", version: "1.3", severity: types.SeverityInfo},
}

func (s *KotlinScanner) handleSSLContextGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	protoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if protoStr == "" {
		return nil
	}

	info, known := sslProtocols[protoStr]
	if !known {
		info = struct {
			name     string
			version  string
			severity types.Severity
		}{name: protoStr, version: "", severity: types.SeverityInfo}
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetProtocol,
		Name:       info.name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   info.severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			ProtocolType:    "tls",
			ProtocolVersion: info.version,
		},
		Description: fmt.Sprintf("SSL/TLS protocol %s via SSLContext.getInstance()", protoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-sslcontext-%s", strings.ToLower(strings.ReplaceAll(protoStr, ".", ""))),
		Pass:        1,
	}
}

func (s *KotlinScanner) detectSSL(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	// SSLContext.getInstance is handled by the JCA detector.
	// This method handles additional SSL-related patterns.
	_ = root
	_ = path
	_ = content
	_ = cp
	return nil
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
// Returns the resolved value and the confidence level.
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

// buildCipherName creates a human-readable cipher name like "AES-ECB".
func buildCipherName(algoClass, mode string) string {
	name := algoClass
	if mode != "" {
		name = fmt.Sprintf("%s-%s", algoClass, strings.ToUpper(mode))
	}
	return name
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

// ---------------------------------------------------------------------------
// PBEKeySpec (PBKDF2) detection
// ---------------------------------------------------------------------------

func (s *KotlinScanner) detectPBEKeySpec(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for new PBEKeySpec(password, salt, iterationCount, keyLength)
	queryStr := `(object_creation_expression
		type: (type_identifier) @cls
		arguments: (argument_list) @args
		(#eq? @cls "PBEKeySpec"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var clsNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0: // @cls
				clsNode = capture.Node
			case 1: // @args
				argsNode = capture.Node
			}
		}
		if clsNode == nil || argsNode == nil {
			continue
		}

		callNode := getObjectCreationNode(clsNode)

		// PBEKeySpec(char[] password, byte[] salt, int iterationCount, int keyLength)
		// iterationCount is the 3rd argument (index 2)
		iterations := resolveNthArgInt(argsNode, 2, content, cp)

		severity := types.SeverityInfo
		if s, _ := kdf.CheckKDFIterations("pbkdf2", iterations); s != types.SeverityInfo {
			severity = s
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "PBKDF2",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "kdf",
				AlgorithmFamily: "pbkdf2",
				CryptoFunctions: []string{"derive"},
			},
			Description: "PBKDF2 key derivation via PBEKeySpec()",
			RuleID:      "cbom-kotlin-jca-pbekeyspec-pbkdf2",
			Pass:        1,
		})
	}

	return findings
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
