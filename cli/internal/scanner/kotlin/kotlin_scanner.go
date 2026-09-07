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
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	javaLang "github.com/smacker/go-tree-sitter/java"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/astrules"
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

	// Detect Bouncy Castle asymmetric engines/signers (SM2, ECIES, GOST).
	// Kotlin has no `new` keyword, so these constructor calls parse as
	// call_expression rather than object_creation_expression.
	bcAsymFindings := s.detectBouncyCastleAsymmetric(root, path, content)
	findings = append(findings, bcAsymFindings...)

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

// The Pass-1 detection tables below are loaded from external, replaceable data
// (astrules): the embedded copy at init and, at scan time, an override from
// --ast-rules-dir (astrules.LoadKotlin). Only the tables (token -> crypto
// semantics) are external; the tree-sitter query machinery stays in Go. Kotlin
// runs on the JVM and uses the same JCA/JCE + Bouncy Castle APIs as Java, so it
// reuses the Java astrules row types. The local struct types preserve the exact
// field names the detect sites already use, so wiring them from data required
// no change at the lookup sites. See docs/ast-rules-external-design.md.

type jcaClassT struct {
	primitive string
	ruleTag   string
}

type bcEngineT struct {
	family    string
	name      string
	primitive string
}

type bcDigestT struct {
	family string
	name   string
}

type sslProtoT struct {
	name     string
	version  string
	severity types.Severity
}

var (
	// jcaClassInfo maps JCA factory classes to detection info.
	jcaClassInfo map[string]jcaClassT
	// algorithmFamilyMap maps JCA algorithm names (uppercased) to quantum family names.
	algorithmFamilyMap map[string]string
	// bcEngineAlgorithms maps Bouncy Castle engine class names to algorithm info.
	bcEngineAlgorithms map[string]bcEngineT
	// bcAsymmetricAlgorithms maps Bouncy Castle asymmetric engine/signer class
	// names to quantum-vulnerable public-key schemes (dedicated low-level BC
	// classes, so there are no false positives).
	bcAsymmetricAlgorithms map[string]bcEngineT
	// bcModes maps Bouncy Castle mode class names to mode strings.
	bcModes map[string]string
	// bcDigestAlgorithms maps Bouncy Castle digest class names to algorithm info.
	bcDigestAlgorithms map[string]bcDigestT
	// sslProtocols maps SSLContext.getInstance() protocol strings to info.
	sslProtocols map[string]sslProtoT
)

func init() {
	applyKotlinTables(astrules.MustLoadKotlinEmbedded())
}

// applyKotlinTables (re)populates the package-level detection tables from a
// loaded astrules.KotlinTables. Called at init with the embedded set and again
// by ApplyExternalRules when --ast-rules-dir is given.
func applyKotlinTables(t *astrules.KotlinTables) {
	jca := make(map[string]jcaClassT, len(t.JCAClasses))
	for _, r := range t.JCAClasses {
		jca[r.Class] = jcaClassT{primitive: r.Primitive, ruleTag: r.RuleTag}
	}
	jcaClassInfo = jca

	fam := make(map[string]string, len(t.AlgorithmFamilies))
	for _, r := range t.AlgorithmFamilies {
		fam[r.Name] = r.Family
	}
	algorithmFamilyMap = fam

	eng := make(map[string]bcEngineT, len(t.BCEngines))
	for _, r := range t.BCEngines {
		eng[r.Class] = bcEngineT{family: r.Family, name: r.Name, primitive: r.Primitive}
	}
	bcEngineAlgorithms = eng

	asym := make(map[string]bcEngineT, len(t.BCAsymmetric))
	for _, r := range t.BCAsymmetric {
		asym[r.Class] = bcEngineT{family: r.Family, name: r.Name, primitive: r.Primitive}
	}
	bcAsymmetricAlgorithms = asym

	modes := make(map[string]string, len(t.BCModes))
	for _, r := range t.BCModes {
		modes[r.Class] = r.Mode
	}
	bcModes = modes

	dig := make(map[string]bcDigestT, len(t.BCDigests))
	for _, r := range t.BCDigests {
		dig[r.Class] = bcDigestT{family: r.Family, name: r.Name}
	}
	bcDigestAlgorithms = dig

	ssl := make(map[string]sslProtoT, len(t.SSLProtocols))
	for _, r := range t.SSLProtocols {
		ssl[r.Protocol] = sslProtoT{name: r.Name, version: r.Version, severity: parseKotlinSeverity(r.Severity)}
	}
	sslProtocols = ssl
}

// ApplyExternalRules replaces the active Kotlin Pass-1 tables from an external
// --ast-rules-dir. When dir is empty, or has no kotlin.yml, the embedded tables
// are restored (per-language fallback). Returns an error only when a present
// kotlin.yml is malformed.
func ApplyExternalRules(dir string) error {
	t, err := astrules.LoadKotlin(dir)
	if err != nil {
		return err
	}
	applyKotlinTables(t)
	return nil
}

func parseKotlinSeverity(s string) types.Severity {
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

// lookupAlgoFamily returns the quantum family key for a given algorithm name.
func lookupAlgoFamily(algo string) string {
	upper := strings.ToUpper(algo)
	if fam, ok := algorithmFamilyMap[upper]; ok {
		return fam
	}
	return strings.ToLower(algo)
}

// keyGenReceiver records a KeyPairGenerator/KeyGenerator getInstance finding
// whose key size may be set on a later .initialize(N)/.init(N) call against the
// assigned receiver variable.
type keyGenReceiver struct {
	varName    string
	findingIdx int
	declByte   uint32
	isKeyPair  bool
}

func (s *KotlinScanner) detectJCA(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding
	var receivers []keyGenReceiver

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
				if v, db, ok := receiverVarOfCall(callNode, content); ok {
					receivers = append(receivers, keyGenReceiver{v, len(findings) - 1, db, true})
				}
			}
		case "KeyGenerator":
			finding := s.handleKeyGeneratorGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
				if v, db, ok := receiverVarOfCall(callNode, content); ok {
					receivers = append(receivers, keyGenReceiver{v, len(findings) - 1, db, false})
				}
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
		case "KeyAgreement":
			finding := s.handleKeyAgreementGetInstance(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	// Detect SecretKeySpec constructor calls: new SecretKeySpec(bytes, "AES")
	// In Kotlin this is typically SecretKeySpec(bytes, "AES") without "new",
	// but the Java grammar may still parse it. Also detect Java-style "new".
	s.applyKeyGenInitSizes(root, content, cp, findings, receivers)

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

// handleKeyAgreementGetInstance detects KeyAgreement.getInstance("DH" / "ECDH"
// / "X25519" / "X448"). Mirrors the Java scanner: Kotlin code calls the same
// JCA factory, so the algorithm string maps directly to a quantum family.
func (s *KotlinScanner) handleKeyAgreementGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	algoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if algoStr == "" {
		return nil
	}

	algoFamily := lookupAlgoFamily(algoStr)
	if algoFamily == "" {
		algoFamily = strings.ToLower(algoStr)
	}
	qi := quantum.GetInfo(algoFamily)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       strings.ToUpper(algoStr),
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "key-agree",
			AlgorithmFamily:  algoFamily,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"keyagree"},
		},
		Description: fmt.Sprintf("Key agreement %s via KeyAgreement.getInstance()", algoStr),
		RuleID:      fmt.Sprintf("cbom-kotlin-jca-keyagreement-%s", strings.ToLower(algoStr)),
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

// detectBouncyCastleAsymmetric detects Bouncy Castle SM2 / ECIES / GOST
// engine and signer constructions. The Kotlin scanner parses with the Java
// tree-sitter grammar, under which a Kotlin constructor call without `new`
// (e.g. `SM2Engine()`) parses as a method_invocation whose name is a bare
// identifier. detectBouncyCastle only matches object_creation_expression
// (`new Xxx()`), so these are handled separately here. The class names are
// highly specific BC identifiers, so there are no false positives.
func (s *KotlinScanner) detectBouncyCastleAsymmetric(root *sitter.Node, path string, content []byte) []types.Finding {
	queryStr := `(method_invocation
		name: (identifier) @cls
		arguments: (argument_list))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	var findings []types.Finding
	for _, match := range matches {
		// The query has a single named capture (@cls); take the first capture
		// whose text matches a known asymmetric BC class.
		var clsNode *sitter.Node
		var asymInfo struct {
			family    string
			name      string
			primitive string
		}
		for _, capture := range match.Captures {
			if info, ok := bcAsymmetricAlgorithms[scanner.NodeText(capture.Node, content)]; ok {
				clsNode = capture.Node
				asymInfo = info
				break
			}
		}
		if clsNode == nil {
			continue
		}

		className := scanner.NodeText(clsNode, content)

		// The method_invocation node is the enclosing call; walk up to it.
		callNode := clsNode.Parent()
		for callNode != nil && callNode.Type() != "method_invocation" {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = clsNode
		}

		qi := quantum.GetInfo(asymInfo.family)
		severity := types.SeverityInfo
		if qi.Status == types.QuantumVulnerable || qi.Status == types.Broken {
			severity = types.SeverityMedium
		}

		cryptoFn := []string{"encrypt", "decrypt"}
		if asymInfo.primitive == "signature" {
			cryptoFn = []string{"sign", "verify"}
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       asymInfo.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        asymInfo.primitive,
				AlgorithmFamily:  asymInfo.family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  cryptoFn,
			},
			Description: fmt.Sprintf("Bouncy Castle %s via %s()", asymInfo.name, className),
			RuleID:      fmt.Sprintf("cbom-kotlin-bc-%s-%s", asymInfo.family, strings.ToLower(className)),
			Pass:        1,
		})
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

func (s *KotlinScanner) handleSSLContextGetInstance(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	protoStr, confidence := resolveFirstArg(argsNode, content, cp)
	if protoStr == "" {
		return nil
	}

	info, known := sslProtocols[protoStr]
	if !known {
		info = sslProtoT{name: protoStr, version: "", severity: types.SeverityInfo}
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

// receiverVarOfCall walks up from a method_invocation to recover the variable it
// is assigned to (e.g. `val kpg = KeyPairGenerator.getInstance(...)` -> "kpg").
// Kotlin `val`/`var` declarations parse as variable_declarator under the Java
// grammar. Returns ok=false for calls with no simple identifier receiver
// (e.g. apply{}/also{} implicit receivers, which are not supported).
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
		case "assignment_expression":
			if leftNode := parent.ChildByFieldName("left"); leftNode != nil && leftNode.Type() == "identifier" {
				return scanner.NodeText(leftNode, content), parent.StartByte(), true
			}
		}
		n = parent
	}
	return "", 0, false
}

// kotlinInitCallRe matches `recv.init(N)` / `recv.initialize(N)` where N is an
// integer literal or an identifier resolvable via constant propagation.
var kotlinInitCallRe = regexp.MustCompile(`(\w+)\s*\.\s*(init|initialize)\s*\(\s*(\w+)\s*\)`)

// kotlinInitCallTwoArgRe matches `recv.initialize(random, N)` / `recv.init(random, N)`
// where the key size is the second argument.
var kotlinInitCallTwoArgRe = regexp.MustCompile(`(\w+)\s*\.\s*(init|initialize)\s*\([^,]+,\s*(\w+)\s*\)`)

// kotlinInitCallSizeFirstRe matches `recv.initialize(N, random)` / `recv.init(N, random)`
// where the key size is the first argument — the standard JCA overload ordering
// (KeyPairGenerator.initialize(int keysize, SecureRandom random)). A non-numeric
// first argument resolves to size 0 in patchKeyGenInitSize and is ignored.
var kotlinInitCallSizeFirstRe = regexp.MustCompile(`(\w+)\s*\.\s*(init|initialize)\s*\(\s*(\w+)\s*,[^)]*\)`)

// applyKeyGenInitSizes patches the KeySize of KeyPairGenerator/KeyGenerator
// findings from later recv.initialize(N)/recv.init(N) calls. Kotlin (which has
// no statement terminators) is mis-parsed by the Java tree-sitter grammar —
// chained calls land in ERROR nodes — so this scan is text-based, consistent
// with the Kotlin ConstPropagator's own regex fallback. ECGenParameterSpec
// overloads carry a non-numeric argument and are naturally ignored.
func (s *KotlinScanner) applyKeyGenInitSizes(root *sitter.Node, content []byte, cp *ConstPropagator, findings []types.Finding, receivers []keyGenReceiver) {
	if len(receivers) == 0 {
		return
	}
	for _, m := range kotlinInitCallRe.FindAllSubmatchIndex(content, -1) {
		s.patchKeyGenInitSize(content, cp, findings, receivers, m)
	}
	for _, m := range kotlinInitCallTwoArgRe.FindAllSubmatchIndex(content, -1) {
		s.patchKeyGenInitSize(content, cp, findings, receivers, m)
	}
	for _, m := range kotlinInitCallSizeFirstRe.FindAllSubmatchIndex(content, -1) {
		s.patchKeyGenInitSize(content, cp, findings, receivers, m)
	}
}

func (s *KotlinScanner) patchKeyGenInitSize(content []byte, cp *ConstPropagator, findings []types.Finding, receivers []keyGenReceiver, m []int) {
	recvName := string(content[m[2]:m[3]])
	method := string(content[m[4]:m[5]])
	arg := string(content[m[6]:m[7]])
	size, err := strconv.Atoi(arg)
	if err != nil {
		if v, ok := cp.Resolve(arg); ok {
			size, _ = strconv.Atoi(v)
		}
	}
	if size <= 0 {
		return
	}
	callByte := uint32(m[0]) // #nosec G115 -- m[0] is a byte offset into content, bounded by file size; it only wraps (never panics) on a >4GB single file, which --max-file-size excludes, and a wrap merely mis-orders one key-size association

	best := -1
	var bestByte uint32
	for i, r := range receivers {
		if r.varName != recvName || r.isKeyPair != (method == "initialize") {
			continue
		}
		if r.declByte <= callByte && (best == -1 || r.declByte > bestByte) {
			best, bestByte = i, r.declByte
		}
	}
	if best == -1 {
		return
	}
	idx := receivers[best].findingIdx
	findings[idx].Properties.KeySize = size
	if base := findings[idx].Name; base != "" && !strings.ContainsRune(base, '-') {
		findings[idx].Name = fmt.Sprintf("%s-%d", base, size)
	}
}

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
