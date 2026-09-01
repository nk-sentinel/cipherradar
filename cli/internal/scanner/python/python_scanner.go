package python

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	python "github.com/smacker/go-tree-sitter/python"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/astrules"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// PythonScanner detects cryptographic API usage in Python source files.
type PythonScanner struct {
	lang *sitter.Language
}

// New creates a new PythonScanner instance.
func New() *PythonScanner {
	return &PythonScanner{
		lang: python.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *PythonScanner) Name() string {
	return "python"
}

// Extensions returns the file extensions this scanner handles.
func (s *PythonScanner) Extensions() []string {
	return []string{".py", ".pyw"}
}

// ScanFile scans a single Python file's content and returns cryptographic findings.
func (s *PythonScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
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

	// Detect hashlib usage
	hashFindings := s.detectHashlib(root, path, content, cp)
	findings = append(findings, hashFindings...)

	// Detect cryptography library usage
	cryptoFindings := s.detectCryptographyLib(root, path, content, cp)
	findings = append(findings, cryptoFindings...)

	// Detect ssl module usage
	sslFindings := s.detectSSL(root, path, content, cp)
	findings = append(findings, sslFindings...)

	// Detect PyCryptodome usage
	pycryptoFindings := s.detectPyCryptodome(root, path, content, cp)
	findings = append(findings, pycryptoFindings...)

	// Detect PyCryptodome cipher/hash constructor calls (AES.new(...), ARC4.new(...), etc.)
	pycryptoUsageFindings := s.detectPyCryptodomeUsage(root, path, content, cp)
	findings = append(findings, pycryptoUsageFindings...)

	// Detect pyca one-shot AEAD constructors (AESGCM, AESCCM, AESSIV, ChaCha20Poly1305)
	pycaAEADFindings := s.detectPycaAEAD(root, path, content, cp)
	findings = append(findings, pycaAEADFindings...)

	// Detect weak PRNG (random module) used for security-sensitive values
	weakRandomFindings := s.detectWeakRandom(root, path, content)
	findings = append(findings, weakRandomFindings...)

	// Detect hmac module usage
	hmacFindings := s.detectHMAC(root, path, content, cp)
	findings = append(findings, hmacFindings...)

	// Detect PKCS1v15 padding usage
	pkcs1Findings := s.detectPKCS1v15(root, path, content)
	findings = append(findings, pkcs1Findings...)

	// F10: Detect Fernet/MultiFernet usage
	fernetFindings := s.detectFernet(root, path, content)
	findings = append(findings, fernetFindings...)

	// F11: Detect CMAC and Poly1305 MAC usage
	cryptoMACFindings := s.detectCryptoMACs(root, path, content)
	findings = append(findings, cryptoMACFindings...)

	// #33: Detect BLS12-381 signatures (py_ecc.bls / blspy / blst)
	findings = append(findings, s.detectBLSPython(root, path, content)...)

	// #33: Detect Schnorr (BIP-340) signatures (coincurve / secp256k1)
	findings = append(findings, s.detectSchnorrPython(root, path, content)...)

	// Detect SM2 (gmssl), ECIES (eciespy), and GOST (gostcrypto) usage
	tier2Findings := s.detectTier2Asymmetric(root, path, content)
	findings = append(findings, tier2Findings...)

	return scanner.AnnotateFindings(findings), nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// hashlib detection
// ---------------------------------------------------------------------------

// The Python Pass-1 detection tables below are DATA, loaded from the embedded
// scanner/ast-rules/python.yml at init() and replaceable at scan time via
// --ast-rules-dir (astrules.LoadPython). Only the tables (token -> crypto
// semantics) are external; the tree-sitter query machinery stays in Go. See
// docs/ast-rules-external-design.md. The local struct types preserve the exact
// field names the detect sites already use, so wiring them from data required
// no change at the lookup sites.

type cipherAlgoT struct {
	family    string
	primitive string
}

type classInfoT struct {
	family string
	name   string
}

type cryptoInfoT struct {
	family    string
	name      string
	primitive string
}

type sslProtoT struct {
	name     string
	version  string
	severity types.Severity
}

type aeadT struct {
	family string
	name   string
	mode   string
}

var (
	// hashlibMethodAlgorithms maps hashlib method names to algorithm family names.
	hashlibMethodAlgorithms map[string]string
	// hashlibMethodNames maps hashlib method names to human-readable names.
	hashlibMethodNames map[string]string
	// hashlibNewAlgorithms maps string arguments to hashlib.new() to algorithm families.
	hashlibNewAlgorithms map[string]string
	// hashlibNewNames maps string arguments to hashlib.new() to human-readable names.
	hashlibNewNames map[string]string
	// cipherAlgoMap maps cryptography.hazmat algorithm class names to algorithm families.
	cipherAlgoMap map[string]cipherAlgoT
	// cipherModeMap maps mode class names to their lowercase identifiers.
	cipherModeMap map[string]string
	// cryptoHashMap maps cryptography hash class names to algorithm families.
	cryptoHashMap map[string]classInfoT
	// kdfMap maps KDF class names to their algorithm families and descriptions.
	kdfMap map[string]classInfoT
	// sslProtocolMap maps ssl.PROTOCOL_* constants to protocol info.
	sslProtocolMap map[string]sslProtoT
	// sslTLSVersionMap maps ssl.TLSVersion.* constants to version info.
	sslTLSVersionMap map[string]sslProtoT
	// pyCryptoImportMap maps PyCryptodome import names to crypto info.
	pyCryptoImportMap map[string]cryptoInfoT
	// pyCryptoCipherUsageMap maps PyCryptodome Cipher class names to crypto info.
	pyCryptoCipherUsageMap map[string]cryptoInfoT
	// pyCryptoHashUsageMap maps PyCryptodome Hash class names to crypto info.
	pyCryptoHashUsageMap map[string]classInfoT
	// pyCryptoModeMap maps PyCryptodome AES.MODE_* constants to mode identifiers.
	pyCryptoModeMap map[string]string
	// pycaAEADMap maps pyca/cryptography one-shot AEAD class names to crypto info.
	pycaAEADMap map[string]aeadT
	// weakRandomMethods are random module functions that produce predictable values.
	weakRandomMethods map[string]bool
	// blsSignMethods are the BLS API entry points (py_ecc.bls / blspy / blst).
	blsSignMethods map[string]string
	// tier2Rules enumerates the precise APIs of the supported Tier-2 libraries.
	tier2Rules []tier2CallRule
)

func init() {
	applyPythonTables(astrules.MustLoadPythonEmbedded())
}

// applyPythonTables (re)populates the package-level detection tables from a
// loaded astrules.PythonTables. Called at init with the embedded set and again
// by ApplyExternalRules when --ast-rules-dir is given.
func applyPythonTables(t *astrules.PythonTables) {
	strMap := func(rows []astrules.PyKV) map[string]string {
		m := make(map[string]string, len(rows))
		for _, r := range rows {
			m[r.Key] = r.Value
		}
		return m
	}

	hashlibMethodAlgorithms = strMap(t.HashlibMethodAlgorithms)
	hashlibMethodNames = strMap(t.HashlibMethodNames)
	hashlibNewAlgorithms = strMap(t.HashlibNewAlgorithms)
	hashlibNewNames = strMap(t.HashlibNewNames)
	cipherModeMap = strMap(t.CipherModes)
	pyCryptoModeMap = strMap(t.PyCryptoModes)
	blsSignMethods = strMap(t.BLSSignMethods)

	ca := make(map[string]cipherAlgoT, len(t.CipherAlgorithms))
	for _, r := range t.CipherAlgorithms {
		ca[r.Class] = cipherAlgoT{family: r.Family, primitive: r.Primitive}
	}
	cipherAlgoMap = ca

	ch := make(map[string]classInfoT, len(t.CryptoHashes))
	for _, r := range t.CryptoHashes {
		ch[r.Class] = classInfoT{family: r.Family, name: r.Name}
	}
	cryptoHashMap = ch

	kd := make(map[string]classInfoT, len(t.KDFs))
	for _, r := range t.KDFs {
		kd[r.Class] = classInfoT{family: r.Family, name: r.Name}
	}
	kdfMap = kd

	sp := make(map[string]sslProtoT, len(t.SSLProtocols))
	for _, r := range t.SSLProtocols {
		sp[r.Const] = sslProtoT{name: r.Name, version: r.Version, severity: parsePythonSeverity(r.Severity)}
	}
	sslProtocolMap = sp

	tv := make(map[string]sslProtoT, len(t.SSLTLSVersions))
	for _, r := range t.SSLTLSVersions {
		tv[r.Const] = sslProtoT{name: r.Name, version: r.Version, severity: parsePythonSeverity(r.Severity)}
	}
	sslTLSVersionMap = tv

	im := make(map[string]cryptoInfoT, len(t.PyCryptoImports))
	for _, r := range t.PyCryptoImports {
		im[r.Imported] = cryptoInfoT{family: r.Family, name: r.Name, primitive: r.Primitive}
	}
	pyCryptoImportMap = im

	cu := make(map[string]cryptoInfoT, len(t.PyCryptoCipherUsage))
	for _, r := range t.PyCryptoCipherUsage {
		cu[r.Class] = cryptoInfoT{family: r.Family, name: r.Name, primitive: r.Primitive}
	}
	pyCryptoCipherUsageMap = cu

	hu := make(map[string]classInfoT, len(t.PyCryptoHashUsage))
	for _, r := range t.PyCryptoHashUsage {
		hu[r.Class] = classInfoT{family: r.Family, name: r.Name}
	}
	pyCryptoHashUsageMap = hu

	ae := make(map[string]aeadT, len(t.PycaAEAD))
	for _, r := range t.PycaAEAD {
		ae[r.Class] = aeadT{family: r.Family, name: r.Name, mode: r.Mode}
	}
	pycaAEADMap = ae

	wr := make(map[string]bool, len(t.WeakRandomMethods))
	for _, m := range t.WeakRandomMethods {
		wr[m] = true
	}
	weakRandomMethods = wr

	rules := make([]tier2CallRule, 0, len(t.Tier2Rules))
	for _, r := range t.Tier2Rules {
		rules = append(rules, tier2CallRule{
			requireImport: r.RequireImport,
			object:        r.Object,
			method:        r.Method,
			family:        r.Family,
			name:          r.Name,
			primitive:     r.Primitive,
			cryptoFn:      r.CryptoFn,
			ruleSuffix:    r.RuleSuffix,
		})
	}
	tier2Rules = rules
}

// ApplyExternalRules replaces the active Python Pass-1 tables from an external
// --ast-rules-dir. When dir is empty, or has no python.yml, the embedded tables
// are restored (per-language fallback). Returns an error only when a present
// python.yml is malformed.
func ApplyExternalRules(dir string) error {
	t, err := astrules.LoadPython(dir)
	if err != nil {
		return err
	}
	applyPythonTables(t)
	return nil
}

func parsePythonSeverity(s string) types.Severity {
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

func (s *PythonScanner) detectHashlib(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Query for hashlib.method() calls
	// Matches: hashlib.md5(), hashlib.sha256(), hashlib.new(), hashlib.pbkdf2_hmac(), etc.
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		arguments: (argument_list) @args
		(#eq? @obj "hashlib"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var methodNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 1: // @method
				methodNode = capture.Node
			case 2: // @args
				argsNode = capture.Node
			}
		}
		if methodNode == nil {
			continue
		}

		methodName := scanner.NodeText(methodNode, content)

		// Get the parent call node for location
		callNode := methodNode.Parent() // attribute node
		if callNode != nil {
			callNode = callNode.Parent() // call node
		}
		if callNode == nil {
			callNode = methodNode
		}

		switch methodName {
		case "new":
			// hashlib.new("algorithm_name")
			finding := s.handleHashlibNew(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "pbkdf2_hmac":
			// hashlib.pbkdf2_hmac("hash_name", password, salt, iterations)
			finding := s.handleHashlibPbkdf2(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		default:
			// Direct hash method: hashlib.md5(), hashlib.sha256(), etc.
			if algoFamily, ok := hashlibMethodAlgorithms[methodName]; ok {
				humanName := hashlibMethodNames[methodName]
				qi := GetQuantumInfo(algoFamily)
				severity := hashSeverity(algoFamily)

				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       humanName,
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   severity,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:        "hash",
						AlgorithmFamily:  algoFamily,
						QuantumStatus:    qi.Status,
						NistQuantumLevel: qi.NistLevel,
						CryptoFunctions:  []string{"digest"},
					},
					Description: fmt.Sprintf("Hash function %s via hashlib.%s()", humanName, methodName),
					RuleID:      fmt.Sprintf("cbom-python-hashlib-%s", methodName),
					Pass:        1,
				})
			}
		}
	}

	return findings
}

func (s *PythonScanner) handleHashlibNew(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	algoName, confidence := resolveFirstArg(argsNode, content, cp)
	if algoName == "" {
		return nil
	}

	normalizedAlgo := strings.ToLower(algoName)
	algoFamily, ok := hashlibNewAlgorithms[normalizedAlgo]
	if !ok {
		// Unrecognized algorithm
		algoFamily = normalizedAlgo
	}
	humanName, ok := hashlibNewNames[normalizedAlgo]
	if !ok {
		humanName = algoName
	}

	qi := GetQuantumInfo(algoFamily)
	severity := hashSeverity(algoFamily)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       humanName,
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
		Description: fmt.Sprintf("Hash function %s via hashlib.new()", humanName),
		RuleID:      "cbom-python-hashlib-new",
		Pass:        1,
	}
}

func (s *PythonScanner) handleHashlibPbkdf2(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	hashName, confidence := resolveFirstArg(argsNode, content, cp)
	if hashName == "" {
		hashName = "unknown"
		confidence = types.ConfidenceLow
	}

	normalizedHash := strings.ToLower(hashName)
	algoFamily, ok := hashlibNewAlgorithms[normalizedHash]
	if !ok {
		algoFamily = normalizedHash
	}

	qi := GetQuantumInfo(algoFamily)
	name := fmt.Sprintf("PBKDF2-HMAC-%s", strings.ToUpper(hashName))
	severity := types.SeverityInfo

	// Try to resolve iteration count (4th argument)
	iterations := resolveNthArgInt(argsNode, 3, content, cp)
	if iterations > 0 && iterations < 100000 {
		severity = types.SeverityMedium
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "kdf",
			AlgorithmFamily:  "pbkdf2",
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"derive"},
		},
		Description: fmt.Sprintf("Key derivation using PBKDF2-HMAC-%s via hashlib.pbkdf2_hmac()", strings.ToUpper(hashName)),
		RuleID:      "cbom-python-hashlib-pbkdf2",
		Pass:        1,
	}
}

// ---------------------------------------------------------------------------
// cryptography library detection
// ---------------------------------------------------------------------------

func (s *PythonScanner) detectCryptographyLib(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Detect cipher algorithm constructors: algorithms.AES(key), algorithms.TripleDES(key), etc.
	findings = append(findings, s.detectCipherAlgorithms(root, path, content, cp)...)

	// Detect hash constructors: hashes.SHA256(), hashes.MD5(), etc.
	findings = append(findings, s.detectCryptoHashes(root, path, content, cp)...)

	// Detect asymmetric key generation: rsa.generate_private_key(), ec.generate_private_key(), etc.
	findings = append(findings, s.detectAsymmetricKeyGen(root, path, content, cp)...)

	// Detect KDF usage: PBKDF2HMAC(), HKDF(), Scrypt()
	findings = append(findings, s.detectKDFs(root, path, content, cp)...)

	// Detect Ed25519/Ed448 key generation
	findings = append(findings, s.detectEdDSAKeyGen(root, path, content)...)

	return findings
}

func (s *PythonScanner) detectCipherAlgorithms(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Match: algorithms.AES(key), algorithms.TripleDES(key), etc.
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @algo)
		arguments: (argument_list) @args
		(#eq? @obj "algorithms"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var algoNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 1 { // @algo
				algoNode = capture.Node
			}
		}
		if algoNode == nil {
			continue
		}

		algoClassName := scanner.NodeText(algoNode, content)
		info, ok := cipherAlgoMap[algoClassName]
		if !ok {
			continue
		}

		// Try to detect the mode by looking at the parent Cipher() call context
		mode := detectCipherMode(algoNode, content)

		callNode := algoNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = algoNode
		}

		qi := GetQuantumInfo(info.family)
		severity := cipherSeverity(info.family, mode)

		humanName := buildCipherName(algoClassName, mode)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       humanName,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        info.primitive,
				AlgorithmFamily:  info.family,
				Mode:             mode,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt", "decrypt"},
			},
			Description: fmt.Sprintf("Cipher algorithm %s via cryptography library", humanName),
			RuleID:      fmt.Sprintf("cbom-python-cryptography-%s", strings.ToLower(algoClassName)),
			Pass:        1,
		})
	}

	return findings
}

// detectCipherMode attempts to find the cipher mode used alongside an algorithm.
// It looks for modes.CBC, modes.GCM, etc. in the vicinity.
func detectCipherMode(algoNode *sitter.Node, content []byte) string {
	// Walk up to find the Cipher() call, then look for modes.XXX in arguments
	node := algoNode
	for i := 0; i < 6 && node != nil; i++ {
		node = node.Parent()
		if node == nil {
			break
		}
		if node.Type() == "call" {
			// Check if this is a Cipher() call
			fnNode := node.ChildByFieldName("function")
			if fnNode != nil {
				fnText := fnNode.Content(content)
				if fnText == "Cipher" || strings.HasSuffix(fnText, ".Cipher") {
					// Look for modes.XXX in arguments
					argsNode := node.ChildByFieldName("arguments")
					if argsNode != nil {
						return findModeInArgs(argsNode, content)
					}
				}
			}
		}
	}
	return ""
}

func findModeInArgs(argsNode *sitter.Node, content []byte) string {
	text := argsNode.Content(content)
	for modeName, modeID := range cipherModeMap {
		if strings.Contains(text, "modes."+modeName) {
			return modeID
		}
	}
	return ""
}

func (s *PythonScanner) detectCryptoHashes(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Match: hashes.SHA256(), hashes.MD5(), etc.
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @hash)
		(#eq? @obj "hashes"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var hashNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 1 { // @hash
				hashNode = capture.Node
			}
		}
		if hashNode == nil {
			continue
		}

		hashClassName := scanner.NodeText(hashNode, content)
		info, ok := cryptoHashMap[hashClassName]
		if !ok {
			continue
		}

		// If this is hashes.Hash(hashes.XXX()), skip the Hash wrapper itself
		if hashClassName == "Hash" {
			continue
		}

		callNode := hashNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = hashNode
		}

		qi := GetQuantumInfo(info.family)
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
			Description: fmt.Sprintf("Hash function %s via cryptography library", info.name),
			RuleID:      fmt.Sprintf("cbom-python-cryptography-hash-%s", strings.ToLower(hashClassName)),
			Pass:        1,
		})
	}

	return findings
}

func (s *PythonScanner) detectAsymmetricKeyGen(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Match: rsa.generate_private_key(...), ec.generate_private_key(...), dh.generate_parameters(...)
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		arguments: (argument_list) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
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

		callNode := methodNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = methodNode
		}

		switch {
		case objName == "rsa" && methodName == "generate_private_key":
			keySize := resolveKeywordArgInt(argsNode, "key_size", content, cp)
			severity := types.SeverityInfo
			if keySize > 0 && keySize < 2048 {
				severity = types.SeverityHigh
			}
			qi := GetQuantumInfo("rsa")
			name := "RSA"
			if keySize > 0 {
				name = fmt.Sprintf("RSA-%d", keySize)
			}
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
				Description: fmt.Sprintf("RSA key generation (key_size=%d) via cryptography library", keySize),
				RuleID:      "cbom-python-cryptography-rsa-generate",
				Pass:        1,
			})

		case objName == "ec" && methodName == "generate_private_key":
			// Try to extract curve name from first argument: ec.SECP256R1()
			curveName := extractCurveName(argsNode, content)
			qi := GetQuantumInfo("ec")
			name := "EC"
			if curveName != "" {
				name = fmt.Sprintf("EC-%s", curveName)
			}
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "key-agree",
					AlgorithmFamily:  "ec",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: fmt.Sprintf("EC key generation (%s) via cryptography library", curveName),
				RuleID:      "cbom-python-cryptography-ec-generate",
				Pass:        1,
			})

		case objName == "dh" && methodName == "generate_parameters":
			keySize := resolveKeywordArgInt(argsNode, "key_size", content, cp)
			qi := GetQuantumInfo("dh")
			name := "DH"
			if keySize > 0 {
				name = fmt.Sprintf("DH-%d", keySize)
			}
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "key-agree",
					AlgorithmFamily:  "dh",
					KeySize:          keySize,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: fmt.Sprintf("DH parameter generation (key_size=%d) via cryptography library", keySize),
				RuleID:      "cbom-python-cryptography-dh-generate",
				Pass:        1,
			})

		case objName == "dsa" && methodName == "generate_private_key":
			keySize := resolveNthArgInt(argsNode, 0, content, cp)
			qi := GetQuantumInfo("dsa")
			name := "DSA"
			if keySize > 0 {
				name = fmt.Sprintf("DSA-%d", keySize)
			}
			sev := types.SeverityMedium
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   sev,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "signature",
					AlgorithmFamily:  "dsa",
					KeySize:          keySize,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: fmt.Sprintf("DSA key generation (key_size=%d) via cryptography library", keySize),
				RuleID:      "cbom-python-cryptography-dsa-generate",
				Pass:        1,
			})
		}
	}

	return findings
}

func (s *PythonScanner) detectEdDSAKeyGen(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match: Ed25519PrivateKey.generate(), Ed448PrivateKey.generate()
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		(#eq? @method "generate"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	eddsaMap := map[string]string{
		"Ed25519PrivateKey": "ed25519",
		"Ed448PrivateKey":   "ed448",
		"X25519PrivateKey":  "x25519",
		"X448PrivateKey":    "x448",
	}

	// Key exchange algorithms use a different primitive than signatures.
	keyExchangeSet := map[string]bool{
		"x25519": true,
		"x448":   true,
	}

	for _, match := range matches {
		var objNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 0 {
				objNode = capture.Node
			}
		}
		if objNode == nil {
			continue
		}

		objName := scanner.NodeText(objNode, content)
		algoFamily, ok := eddsaMap[objName]
		if !ok {
			continue
		}

		callNode := objNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = objNode
		}

		qi := GetQuantumInfo(algoFamily)
		name := strings.ToUpper(algoFamily)

		primitive := "signature"
		if keyExchangeSet[algoFamily] {
			primitive = "key-exchange"
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        primitive,
				AlgorithmFamily:  algoFamily,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"generate"},
			},
			Description: fmt.Sprintf("%s key generation via cryptography library", name),
			RuleID:      fmt.Sprintf("cbom-python-cryptography-%s-generate", algoFamily),
			Pass:        1,
		})

		// Emit internal hash dependency for CBOM completeness.
		// Ed25519 uses SHA-512 internally; Ed448 uses SHAKE256.
		internalHash := map[string]struct{ family, name string }{
			"ed25519": {family: "sha-512", name: "SHA-512"},
			"ed448":   {family: "shake256", name: "SHAKE-256"},
		}
		if ih, ok := internalHash[algoFamily]; ok {
			ihqi := GetQuantumInfo(ih.family)
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       ih.name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  ih.family,
					QuantumStatus:    ihqi.Status,
					NistQuantumLevel: ihqi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("Hash %s (internal to %s)", ih.name, name),
				RuleID:      fmt.Sprintf("cbom-python-internal-hash-%s", strings.ToLower(ih.name)),
				Pass:        1,
			})
		}
	}

	return findings
}

func (s *PythonScanner) detectKDFs(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Match direct constructor calls: PBKDF2HMAC(), HKDF(), Scrypt()
	for className, info := range kdfMap {
		queryStr := fmt.Sprintf(`(call
			function: (identifier) @fn
			(#eq? @fn "%s"))`, className)

		matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
		if err != nil {
			continue
		}

		for _, match := range matches {
			var fnNode *sitter.Node
			for _, capture := range match.Captures {
				if capture.Index == 0 {
					fnNode = capture.Node
				}
			}
			if fnNode == nil {
				continue
			}

			callNode := fnNode.Parent()
			if callNode == nil {
				callNode = fnNode
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       info.name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "kdf",
					AlgorithmFamily: info.family,
					CryptoFunctions: []string{"derive"},
				},
				Description: fmt.Sprintf("Key derivation function %s via cryptography library", info.name),
				RuleID:      fmt.Sprintf("cbom-python-cryptography-kdf-%s", strings.ToLower(className)),
				Pass:        1,
			})

			// F3-P: Extract hash from algorithm= keyword arg (e.g., algorithm=hashes.SHA256()).
			if callNode != nil {
				argsNode := callNode.ChildByFieldName("arguments")
				if argsNode != nil {
					if hashFamily, hashName := extractKDFHashArg(argsNode, content); hashFamily != "" {
						qi := GetQuantumInfo(hashFamily)
						findings = append(findings, types.Finding{
							ID:         nextFindingID(),
							AssetType:  types.AssetAlgorithm,
							Name:       hashName,
							Location:   scanner.NodeLocation(callNode, path, content),
							Severity:   hashSeverity(hashFamily),
							Confidence: types.ConfidenceHigh,
							Properties: types.CryptoProperties{
								Primitive:        "hash",
								AlgorithmFamily:  hashFamily,
								QuantumStatus:    qi.Status,
								NistQuantumLevel: qi.NistLevel,
								CryptoFunctions:  []string{"digest"},
							},
							Description: fmt.Sprintf("Hash %s (extracted from KDF %s)", hashName, info.name),
							RuleID:      "cbom-python-kdf-inner-hash",
							Pass:        1,
						})
					}
				}
			}
		}
	}

	return findings
}

// extractKDFHashArg looks for algorithm=hashes.XXX() in a KDF constructor's argument list.
func extractKDFHashArg(argsNode *sitter.Node, content []byte) (string, string) {
	if argsNode == nil {
		return "", ""
	}
	// Walk children looking for keyword_argument with name "algorithm"
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil || child.Type() != "keyword_argument" {
			continue
		}
		nameNode := child.ChildByFieldName("name")
		valueNode := child.ChildByFieldName("value")
		if nameNode == nil || valueNode == nil {
			continue
		}
		if scanner.NodeText(nameNode, content) != "algorithm" {
			continue
		}
		// valueNode should be a call like hashes.SHA256()
		valText := scanner.NodeText(valueNode, content)
		hashClasses := map[string]struct{ family, name string }{
			"SHA256": {"sha-256", "SHA-256"}, "SHA384": {"sha-384", "SHA-384"},
			"SHA512": {"sha-512", "SHA-512"}, "SHA1": {"sha1", "SHA-1"},
			"MD5": {"md5", "MD5"}, "SHA224": {"sha-224", "SHA-224"},
			"SHA3_256": {"sha3-256", "SHA3-256"}, "SHA3_384": {"sha3-384", "SHA3-384"},
			"SHA3_512": {"sha3-512", "SHA3-512"},
			"BLAKE2b":  {"blake2b", "BLAKE2b"}, "BLAKE2s": {"blake2s", "BLAKE2s"},
		}
		for cls, info := range hashClasses {
			if strings.Contains(valText, "hashes."+cls) || strings.Contains(valText, cls+"()") {
				return info.family, info.name
			}
		}
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// ssl module detection
// ---------------------------------------------------------------------------

// extractSSLProtocol walks the argument list nodes to find an ssl.PROTOCOL_*
// attribute access and returns the matched protocol constant name and its info.
// This avoids substring matching issues (e.g. PROTOCOL_TLS matching PROTOCOL_TLSv1).
func extractSSLProtocol(argsNode *sitter.Node, content []byte) (string, struct {
	name     string
	version  string
	severity types.Severity
}) {
	type protoInfo struct {
		name     string
		version  string
		severity types.Severity
	}
	empty := struct {
		name     string
		version  string
		severity types.Severity
	}{}

	// Walk child nodes looking for attribute access ssl.PROTOCOL_*
	var found string
	walkForProtocol(argsNode, content, &found)
	if found == "" {
		return "", empty
	}

	if info, ok := sslProtocolMap[found]; ok {
		return found, info
	}
	return "", empty
}

// walkForProtocol recursively searches nodes for ssl.PROTOCOL_* attribute accesses.
func walkForProtocol(node *sitter.Node, content []byte, result *string) {
	if node == nil || *result != "" {
		return
	}
	if node.Type() == "attribute" {
		objNode := node.ChildByFieldName("object")
		attrNode := node.ChildByFieldName("attribute")
		if objNode != nil && attrNode != nil {
			if objNode.Type() == "identifier" && objNode.Content(content) == "ssl" {
				attrName := attrNode.Content(content)
				if strings.HasPrefix(attrName, "PROTOCOL_") {
					*result = attrName
					return
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			walkForProtocol(child, content, result)
		}
	}
}

func (s *PythonScanner) detectSSL(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Detect ssl.SSLContext(ssl.PROTOCOL_*)
	findings = append(findings, s.detectSSLContext(root, path, content)...)

	// Detect ssl.TLSVersion.* assignments
	findings = append(findings, s.detectTLSVersion(root, path, content)...)

	// Detect ssl.CERT_NONE
	findings = append(findings, s.detectCertNone(root, path, content)...)

	// Detect ssl.wrap_socket (deprecated)
	findings = append(findings, s.detectWrapSocket(root, path, content)...)

	return findings
}

func (s *PythonScanner) detectSSLContext(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match: ssl.SSLContext(ssl.PROTOCOL_*)
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		arguments: (argument_list) @args
		(#eq? @obj "ssl")
		(#eq? @method "SSLContext"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var argsNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 2 { // @args
				argsNode = capture.Node
			}
		}
		if argsNode == nil {
			continue
		}

		// Get the call node
		callNode := argsNode.Parent()
		if callNode == nil {
			continue
		}

		// Extract the protocol constant from arguments by looking for ssl.PROTOCOL_*
		// attribute access nodes inside the argument list
		proto, info := extractSSLProtocol(argsNode, content)
		if proto == "" {
			continue
		}

		description := fmt.Sprintf("SSL/TLS context using %s", info.name)
		if info.severity == types.SeverityHigh {
			description = fmt.Sprintf("Deprecated SSL/TLS protocol %s", info.name)
		}
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetProtocol,
			Name:       info.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   info.severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				ProtocolType:    "tls",
				ProtocolVersion: info.version,
			},
			Description: description,
			RuleID:      fmt.Sprintf("cbom-python-ssl-%s", strings.ToLower(proto)),
			Pass:        1,
		})
	}

	return findings
}

func (s *PythonScanner) detectTLSVersion(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match attribute access: ssl.TLSVersion.TLSv1_2, etc.
	// This appears in assignments like: ctx.minimum_version = ssl.TLSVersion.TLSv1_2
	queryStr := `(attribute
		object: (attribute
			object: (identifier) @ssl_mod
			attribute: (identifier) @tls_ver_cls)
		attribute: (identifier) @version
		(#eq? @ssl_mod "ssl")
		(#eq? @tls_ver_cls "TLSVersion"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var versionNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 2 { // @version
				versionNode = capture.Node
			}
		}
		if versionNode == nil {
			continue
		}

		versionName := scanner.NodeText(versionNode, content)
		info, ok := sslTLSVersionMap[versionName]
		if !ok {
			continue
		}

		// Get the enclosing attribute node
		attrNode := versionNode.Parent()
		if attrNode == nil {
			attrNode = versionNode
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetProtocol,
			Name:       info.name,
			Location:   scanner.NodeLocation(attrNode, path, content),
			Severity:   info.severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				ProtocolType:    "tls",
				ProtocolVersion: info.version,
			},
			Description: fmt.Sprintf("TLS version constraint: %s", info.name),
			RuleID:      fmt.Sprintf("cbom-python-ssl-tlsversion-%s", strings.ToLower(versionName)),
			Pass:        1,
		})
	}

	return findings
}

func (s *PythonScanner) detectCertNone(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match: ssl.CERT_NONE
	queryStr := `(attribute
		object: (identifier) @obj
		attribute: (identifier) @attr
		(#eq? @obj "ssl")
		(#eq? @attr "CERT_NONE"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var attrNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 1 { // @attr
				attrNode = capture.Node
			}
		}
		if attrNode == nil {
			continue
		}

		node := attrNode.Parent()
		if node == nil {
			node = attrNode
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetProtocol,
			Name:       "Certificate Validation Disabled",
			Location:   scanner.NodeLocation(node, path, content),
			Severity:   types.SeverityCritical,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				ProtocolType: "tls",
			},
			Description: "Certificate validation disabled with ssl.CERT_NONE — vulnerable to MITM attacks",
			RuleID:      "cbom-python-ssl-cert-none",
			Pass:        1,
		})
	}

	return findings
}

func (s *PythonScanner) detectWrapSocket(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match: ssl.wrap_socket(...)
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		(#eq? @obj "ssl")
		(#eq? @method "wrap_socket"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var methodNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 1 { // @method
				methodNode = capture.Node
			}
		}
		if methodNode == nil {
			continue
		}

		callNode := methodNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = methodNode
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetProtocol,
			Name:       "ssl.wrap_socket (deprecated)",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				ProtocolType: "tls",
			},
			Description: "Deprecated ssl.wrap_socket() — use ssl.SSLContext instead",
			RuleID:      "cbom-python-ssl-wrap-socket",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// PyCryptodome detection
// ---------------------------------------------------------------------------

func (s *PythonScanner) detectPyCryptodome(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Match: from Crypto.Cipher import AES
	// Match: from Crypto.Hash import SHA256
	// Match: from Crypto.PublicKey import RSA
	queryStr := `(import_from_statement
		module_name: (dotted_name) @module
		name: (dotted_name) @imported)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var moduleNode, importedNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				moduleNode = capture.Node
			case 1:
				importedNode = capture.Node
			}
		}
		if moduleNode == nil || importedNode == nil {
			continue
		}

		moduleName := scanner.NodeText(moduleNode, content)
		importedName := scanner.NodeText(importedNode, content)

		// Only match Crypto.* or Cryptodome.* imports
		if !strings.HasPrefix(moduleName, "Crypto.") && !strings.HasPrefix(moduleName, "Cryptodome.") {
			continue
		}

		info, ok := pyCryptoImportMap[importedName]
		if !ok {
			continue
		}

		// Use the import statement node
		stmtNode := moduleNode.Parent()
		if stmtNode == nil {
			stmtNode = moduleNode
		}

		qi := GetQuantumInfo(info.family)
		severity := types.SeverityInfo
		if qi.Status == types.Broken {
			severity = types.SeverityHigh
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       info.name,
			Location:   scanner.NodeLocation(stmtNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        info.primitive,
				AlgorithmFamily:  info.family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
			},
			Description: fmt.Sprintf("PyCryptodome import: %s from %s", importedName, moduleName),
			RuleID:      fmt.Sprintf("cbom-python-pycryptodome-%s", strings.ToLower(importedName)),
			Pass:        1,
		})
	}

	return findings
}

// collectImportedNames returns the set of symbols imported via `from <module> import <name>`
// statements whose module name satisfies modulePredicate. Used to gate usage/constructor
// detection so we only flag calls to classes that were actually imported from the relevant
// library (zero-FP discipline — a bare `AES.new(...)` in unrelated code is not flagged).
func collectImportedNames(root *sitter.Node, content []byte, lang *sitter.Language, modulePredicate func(string) bool) map[string]bool {
	imported := make(map[string]bool)

	queryStr := `(import_from_statement
		module_name: (dotted_name) @module)`
	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return imported
	}

	for _, match := range matches {
		var moduleNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 0 {
				moduleNode = capture.Node
			}
		}
		if moduleNode == nil {
			continue
		}
		moduleName := scanner.NodeText(moduleNode, content)
		if !modulePredicate(moduleName) {
			continue
		}
		// The import statement is the parent of module_name. Walk its children for
		// imported names (dotted_name / aliased_import) that follow the module name.
		stmt := moduleNode.Parent()
		if stmt == nil {
			continue
		}
		for i := 0; i < int(stmt.NamedChildCount()); i++ {
			child := stmt.NamedChild(i)
			if child == nil || child == moduleNode {
				continue
			}
			switch child.Type() {
			case "dotted_name", "identifier":
				imported[scanner.NodeText(child, content)] = true
			case "aliased_import":
				if nameNode := child.ChildByFieldName("name"); nameNode != nil {
					imported[scanner.NodeText(nameNode, content)] = true
				}
			}
		}
	}

	return imported
}

// collectImportAliases is like collectImportedNames but returns the *local
// alias* introduced by `from <module> import <symbol> as <alias>` (the "alias"
// field of an aliased_import), for modules satisfying modulePredicate. Needed
// because library usage typically references the alias, not the original symbol
// (e.g. `from py_ecc.bls import G2ProofOfPossession as bls`).
func collectImportAliases(root *sitter.Node, content []byte, lang *sitter.Language, modulePredicate func(string) bool) map[string]bool {
	aliases := make(map[string]bool)

	queryStr := `(import_from_statement
		module_name: (dotted_name) @module)`
	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return aliases
	}

	for _, match := range matches {
		var moduleNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 0 {
				moduleNode = capture.Node
			}
		}
		if moduleNode == nil || !modulePredicate(scanner.NodeText(moduleNode, content)) {
			continue
		}
		stmt := moduleNode.Parent()
		if stmt == nil {
			continue
		}
		for i := 0; i < int(stmt.NamedChildCount()); i++ {
			child := stmt.NamedChild(i)
			if child == nil || child.Type() != "aliased_import" {
				continue
			}
			if aliasNode := child.ChildByFieldName("alias"); aliasNode != nil {
				aliases[scanner.NodeText(aliasNode, content)] = true
			}
		}
	}

	return aliases
}

// ---------------------------------------------------------------------------
// PyCryptodome usage detection (Crypto.Cipher.* / Crypto.Hash.* constructors)
// ---------------------------------------------------------------------------

// detectPyCryptodomeUsage detects PyCryptodome cipher/hash constructor calls such as
// `AES.new(key, AES.MODE_GCM)`, `ARC4.new(key)`, `ChaCha20_Poly1305.new(key=key)` and
// `BLAKE2b.new(data=data)`. Detection is gated on the class having been imported from a
// Crypto.* / Cryptodome.* module to avoid false positives.
func (s *PythonScanner) detectPyCryptodomeUsage(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	imported := collectImportedNames(root, content, s.lang, func(m string) bool {
		return strings.HasPrefix(m, "Crypto.") || strings.HasPrefix(m, "Cryptodome.")
	})
	if len(imported) == 0 {
		return nil
	}

	var findings []types.Finding

	// Match: ClassName.new(...)
	queryStr := `(call
		function: (attribute
			object: (identifier) @cls
			attribute: (identifier) @method)
		arguments: (argument_list) @args
		(#eq? @method "new"))`

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
			case 2: // @args
				argsNode = capture.Node
			}
		}
		if clsNode == nil {
			continue
		}

		className := scanner.NodeText(clsNode, content)
		if !imported[className] {
			continue
		}

		callNode := clsNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = clsNode
		}

		if info, ok := pyCryptoCipherUsageMap[className]; ok {
			// Determine the mode from the second positional argument (AES.MODE_*).
			mode := findPyCryptoMode(argsNode, content)
			// ChaCha20-Poly1305 and one-shot AEADs carry an implicit AEAD mode.
			humanName := info.name
			if mode != "" {
				humanName = buildCipherName(info.name, mode)
			}
			qi := GetQuantumInfo(info.family)
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       humanName,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   cipherSeverity(info.family, mode),
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        info.primitive,
					AlgorithmFamily:  info.family,
					Mode:             mode,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt", "decrypt"},
				},
				Description: fmt.Sprintf("Cipher %s via PyCryptodome", humanName),
				RuleID:      fmt.Sprintf("cbom-python-pycryptodome-%s-usage", strings.ToLower(className)),
				Pass:        1,
			})
			continue
		}

		if info, ok := pyCryptoHashUsageMap[className]; ok {
			qi := GetQuantumInfo(info.family)
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       info.name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   hashSeverity(info.family),
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  info.family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("Hash %s via PyCryptodome", info.name),
				RuleID:      fmt.Sprintf("cbom-python-pycryptodome-%s-usage", strings.ToLower(className)),
				Pass:        1,
			})
		}
	}

	return findings
}

// findPyCryptoMode scans an argument list for a PyCryptodome MODE_* constant
// (e.g. AES.MODE_GCM or a bare MODE_GCM) and returns its mode identifier.
func findPyCryptoMode(argsNode *sitter.Node, content []byte) string {
	if argsNode == nil {
		return ""
	}
	text := argsNode.Content(content)
	for modeConst, modeID := range pyCryptoModeMap {
		if strings.Contains(text, modeConst) {
			return modeID
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// pyca one-shot AEAD detection (cryptography.hazmat.primitives.ciphers.aead)
// ---------------------------------------------------------------------------

// detectPycaAEAD detects pyca/cryptography one-shot AEAD constructors such as
// `AESGCM(key)`, `AESCCM(key)`, `AESSIV(key)`, `ChaCha20Poly1305(key)`. Detection is
// gated on the class being imported from cryptography.hazmat.primitives.ciphers.aead.
func (s *PythonScanner) detectPycaAEAD(root *sitter.Node, path string, content []byte, _ *ConstPropagator) []types.Finding {
	imported := collectImportedNames(root, content, s.lang, func(m string) bool {
		return m == "cryptography.hazmat.primitives.ciphers.aead"
	})
	if len(imported) == 0 {
		return nil
	}

	var findings []types.Finding

	// Match: AEADClass(...) — a direct call on an identifier.
	queryStr := `(call
		function: (identifier) @cls
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
		if !imported[className] {
			continue
		}
		info, ok := pycaAEADMap[className]
		if !ok {
			continue
		}

		callNode := clsNode.Parent()
		if callNode == nil {
			callNode = clsNode
		}

		qi := GetQuantumInfo(info.family)
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
				Mode:             info.mode,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt", "decrypt"},
			},
			Description: fmt.Sprintf("AEAD cipher %s via cryptography library", info.name),
			RuleID:      fmt.Sprintf("cbom-python-cryptography-aead-%s", strings.ToLower(className)),
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Weak PRNG (random module) for security-sensitive values
// ---------------------------------------------------------------------------

// securityContextRE matches identifiers (enclosing function names or assignment
// targets) that strongly imply a security-sensitive use of randomness. Gating on
// this keeps detection zero-FP for the overwhelmingly common non-security uses of
// the random module (games, sampling, jitter, tests).
var securityContextRE = regexp.MustCompile(`(?i)token|password|passwd|secret|nonce|salt|\bkey\b|otp|session|csrf|crypt|auth|cred|apikey`)

// detectWeakRandom flags random.<method>() calls used for security-sensitive values.
// It requires (a) the `random` module to be imported and (b) the enclosing function
// name to look security-related, so unrelated random usage is never flagged.
func (s *PythonScanner) detectWeakRandom(root *sitter.Node, path string, content []byte) []types.Finding {
	// Gate on `import random` being present.
	if !hasRandomImport(root, content, s.lang) {
		return nil
	}

	var findings []types.Finding

	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		(#eq? @obj "random"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var methodNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 1 { // @method
				methodNode = capture.Node
			}
		}
		if methodNode == nil {
			continue
		}
		methodName := scanner.NodeText(methodNode, content)
		if !weakRandomMethods[methodName] {
			continue
		}

		callNode := methodNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = methodNode
		}

		if !inSecurityContext(callNode, content) {
			continue
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "Weak PRNG (random)",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityHigh,
			Confidence: types.ConfidenceMedium,
			Properties: types.CryptoProperties{
				Primitive:       "drbg",
				AlgorithmFamily: "random",
				QuantumStatus:   types.QuantumSafe,
				CryptoFunctions: []string{"generate"},
			},
			Description: "Non-cryptographic random.* used for a security-sensitive value; use secrets or os.urandom()",
			RuleID:      "cbom-python-weak-random",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Tier-2 asymmetric detection: SM2 (gmssl), ECIES (eciespy), GOST (gostcrypto)
// ---------------------------------------------------------------------------

// collectModuleTokens returns the set of module/symbol tokens introduced by
// `import ...` and `from ... import ...` statements. For dotted module names it
// records both the full dotted path and the leading component (e.g. `gmssl.sm2`
// yields {"gmssl.sm2", "gmssl"}). `from gmssl import sm2` records both the
// module (`gmssl`) and the imported symbol (`sm2`). This lets Tier-2 detection
// gate strictly on the relevant library actually being imported (zero FP).
func collectModuleTokens(root *sitter.Node, content []byte, lang *sitter.Language) map[string]bool {
	tokens := make(map[string]bool)
	add := func(name string) {
		if name == "" {
			return
		}
		tokens[name] = true
		if i := strings.Index(name, "."); i > 0 {
			tokens[name[:i]] = true
		}
	}

	// `import a`, `import a.b`, `import a as b`
	for _, match := range queryAll(root, content, lang, `(import_statement (dotted_name) @mod)`) {
		add(match)
	}
	for _, match := range queryAll(root, content, lang, `(import_statement (aliased_import (dotted_name) @mod))`) {
		add(match)
	}
	// `from a.b import c` — record both the module path and each imported symbol.
	for _, match := range queryAll(root, content, lang, `(import_from_statement module_name: (dotted_name) @mod)`) {
		add(match)
	}
	for _, match := range queryAll(root, content, lang, `(import_from_statement name: (dotted_name) @sym)`) {
		add(match)
	}
	for _, match := range queryAll(root, content, lang, `(import_from_statement (aliased_import (dotted_name) @sym))`) {
		add(match)
	}
	return tokens
}

// queryAll runs a single-capture tree-sitter query and returns the text of
// every captured node.
func queryAll(root *sitter.Node, content []byte, lang *sitter.Language, queryStr string) []string {
	var out []string
	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return out
	}
	for _, match := range matches {
		for _, capture := range match.Captures {
			out = append(out, scanner.NodeText(capture.Node, content))
		}
	}
	return out
}

// tier2CallRule ties a specific call (object.method or bare function) to a
// quantum-vulnerable algorithm family, gated on a required import token.
type tier2CallRule struct {
	requireImport string // import token that must be present (e.g. "gmssl")
	object        string // selector object, e.g. "sm2"; "" matches bare calls
	method        string // method/function name, e.g. "CryptSM2", "encrypt"
	family        string // quantum family (sm2 / ecies / gost)
	name          string // human-readable algorithm name
	primitive     string
	cryptoFn      string
	ruleSuffix    string
}

func (s *PythonScanner) detectTier2Asymmetric(root *sitter.Node, path string, content []byte) []types.Finding {
	imports := collectModuleTokens(root, content, s.lang)
	if len(imports) == 0 {
		return nil
	}

	var findings []types.Finding
	seen := make(map[string]bool) // dedupe object.method/bare overlaps per location

	for _, rule := range tier2Rules {
		if !imports[rule.requireImport] {
			continue
		}

		var queryStr string
		if rule.object != "" {
			// object.method(...)
			queryStr = fmt.Sprintf(`(call
				function: (attribute
					object: (identifier) @obj
					attribute: (identifier) @method)
				(#eq? @obj "%s")
				(#eq? @method "%s"))`, rule.object, rule.method)
		} else {
			// bare method(...)
			queryStr = fmt.Sprintf(`(call
				function: (identifier) @fn
				(#eq? @fn "%s"))`, rule.method)
		}

		matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
		if err != nil {
			continue
		}

		for _, match := range matches {
			var anchor *sitter.Node
			for _, capture := range match.Captures {
				anchor = capture.Node
			}
			if anchor == nil {
				continue
			}

			callNode := anchor
			for callNode != nil && callNode.Type() != "call" {
				callNode = callNode.Parent()
			}
			if callNode == nil {
				callNode = anchor
			}

			loc := scanner.NodeLocation(callNode, path, content)
			dedupeKey := fmt.Sprintf("%d:%d:%s", loc.StartLine, loc.StartCol, rule.family)
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			qi := GetQuantumInfo(rule.family)
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       rule.name,
				Location:   loc,
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        rule.primitive,
					AlgorithmFamily:  rule.family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{rule.cryptoFn},
				},
				Description: fmt.Sprintf("%s %s via %s", rule.name, rule.cryptoFn, rule.requireImport),
				RuleID:      fmt.Sprintf("cbom-python-%s", rule.ruleSuffix),
				Pass:        1,
			})
		}
	}

	return findings
}

// hasRandomImport reports whether the file imports the stdlib random module.
func hasRandomImport(root *sitter.Node, content []byte, lang *sitter.Language) bool {
	queryStr := `(import_statement name: (dotted_name) @mod)`
	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return false
	}
	for _, match := range matches {
		for _, capture := range match.Captures {
			if scanner.NodeText(capture.Node, content) == "random" {
				return true
			}
		}
	}
	return false
}

// inSecurityContext reports whether the enclosing function definition (or, lacking
// one, the surrounding assignment target) has a name suggesting security-sensitive use.
func inSecurityContext(node *sitter.Node, content []byte) bool {
	for n := node; n != nil; n = n.Parent() {
		switch n.Type() {
		case "function_definition":
			if nameNode := n.ChildByFieldName("name"); nameNode != nil {
				if securityContextRE.MatchString(scanner.NodeText(nameNode, content)) {
					return true
				}
			}
		case "assignment":
			if left := n.ChildByFieldName("left"); left != nil {
				if securityContextRE.MatchString(scanner.NodeText(left, content)) {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// hmac module detection
// ---------------------------------------------------------------------------

func (s *PythonScanner) detectHMAC(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Match: hmac.new(key, msg, hashlib.sha256) or hmac.new(key, msg, "sha256")
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		arguments: (argument_list) @args
		(#eq? @obj "hmac")
		(#eq? @method "new"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var methodNode, argsNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 1: // @method
				methodNode = capture.Node
			case 2: // @args
				argsNode = capture.Node
			}
		}
		if methodNode == nil {
			continue
		}

		callNode := methodNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = methodNode
		}

		// Try to resolve the hash algorithm from the third argument
		hashAlgo := "unknown"
		confidence := types.ConfidenceLow
		if argsNode != nil {
			hashAlgo, confidence = resolveHMACHashArg(argsNode, content, cp)
		}

		algoFamily := "hmac"
		name := "HMAC"
		if hashAlgo != "unknown" {
			name = fmt.Sprintf("HMAC-%s", strings.ToUpper(hashAlgo))
		}

		findings = append(findings, types.Finding{
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
			Description: fmt.Sprintf("HMAC via hmac.new() with %s", hashAlgo),
			RuleID:      "cbom-python-hmac-new",
			Pass:        1,
		})

		// F2-P: Emit additional finding for the inner hash algorithm.
		if hashAlgo != "unknown" {
			innerHashFamily := lookupHashFamily(hashAlgo)
			qi := GetQuantumInfo(innerHashFamily)
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       strings.ToUpper(hashAlgo),
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   hashSeverity(innerHashFamily),
				Confidence: confidence,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  innerHashFamily,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("Hash %s (extracted from HMAC)", strings.ToUpper(hashAlgo)),
				RuleID:      "cbom-python-hmac-inner-hash",
				Pass:        1,
			})
		}
	}

	return findings
}

// lookupHashFamily normalizes a hash algorithm name to its family key.
func lookupHashFamily(hashAlgo string) string {
	families := map[string]string{
		"sha256": "sha-256", "sha-256": "sha-256",
		"sha384": "sha-384", "sha-384": "sha-384",
		"sha512": "sha-512", "sha-512": "sha-512",
		"sha1": "sha1", "sha-1": "sha1",
		"md5":      "md5",
		"sha3-256": "sha3-256", "sha3-384": "sha3-384", "sha3-512": "sha3-512",
		"blake2b": "blake2b", "blake2s": "blake2s",
	}
	if f, ok := families[strings.ToLower(hashAlgo)]; ok {
		return f
	}
	return strings.ToLower(hashAlgo)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// resolveFirstArg extracts the first positional argument value from an argument list.
// Returns the resolved value and the confidence level.
func resolveFirstArg(argsNode *sitter.Node, content []byte, cp *ConstPropagator) (string, types.Confidence) {
	if argsNode == nil {
		return "", types.ConfidenceLow
	}

	// Find the first child that is an argument (not a parenthesis)
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}

		switch child.Type() {
		case "string":
			return unquotePythonString(child.Content(content)), types.ConfidenceHigh
		case "integer":
			return child.Content(content), types.ConfidenceHigh
		case "identifier":
			name := child.Content(content)
			if val, ok := cp.Resolve(name); ok {
				return val, types.ConfidenceMedium
			}
			return "", types.ConfidenceLow
		case "keyword_argument":
			// Skip keyword arguments when looking for positional args
			continue
		case "(", ")", ",":
			continue
		default:
			// Try extracting from text content
			text := child.Content(content)
			if text != "" && text != "(" && text != ")" && text != "," {
				return text, types.ConfidenceLow
			}
		}
	}

	return "", types.ConfidenceLow
}

// resolveNthArgInt resolves the nth positional argument (0-indexed) to an integer.
// Returns 0 if unable to resolve.
func resolveNthArgInt(argsNode *sitter.Node, n int, content []byte, cp *ConstPropagator) int {
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
		if nodeType == "(" || nodeType == ")" || nodeType == "," || nodeType == "keyword_argument" {
			continue
		}

		if posIdx == n {
			switch nodeType {
			case "integer":
				val, err := strconv.Atoi(child.Content(content))
				if err == nil {
					return val
				}
			case "identifier":
				name := child.Content(content)
				if resolved, ok := cp.Resolve(name); ok {
					val, err := strconv.Atoi(resolved)
					if err == nil {
						return val
					}
				}
			}
			return 0
		}
		posIdx++
	}

	return 0
}

// resolveKeywordArgInt looks for a keyword argument with the given name and resolves its integer value.
func resolveKeywordArgInt(argsNode *sitter.Node, keyword string, content []byte, cp *ConstPropagator) int {
	if argsNode == nil {
		return 0
	}

	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil || child.Type() != "keyword_argument" {
			continue
		}

		// keyword_argument has name and value
		nameNode := child.ChildByFieldName("name")
		valueNode := child.ChildByFieldName("value")
		if nameNode == nil || valueNode == nil {
			continue
		}

		if nameNode.Content(content) != keyword {
			continue
		}

		switch valueNode.Type() {
		case "integer":
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

// extractCurveName extracts an EC curve name from function arguments.
// Handles patterns like: ec.SECP256R1()
func extractCurveName(argsNode *sitter.Node, content []byte) string {
	if argsNode == nil {
		return ""
	}

	argsText := argsNode.Content(content)

	// Known curves
	curves := []string{
		"SECP256R1", "SECP384R1", "SECP521R1",
		"SECP256K1", "SECP224R1", "SECP192R1",
		"BrainpoolP256R1", "BrainpoolP384R1", "BrainpoolP512R1",
	}

	for _, curve := range curves {
		if strings.Contains(argsText, curve) {
			return curve
		}
	}

	return ""
}

// resolveHMACHashArg tries to resolve the hash algorithm from hmac.new() arguments.
// The hash can be the third positional arg or the digestmod keyword argument.
func resolveHMACHashArg(argsNode *sitter.Node, content []byte, cp *ConstPropagator) (string, types.Confidence) {
	if argsNode == nil {
		return "unknown", types.ConfidenceLow
	}

	argsText := argsNode.Content(content)

	// Check for hashlib.XXX reference in arguments
	for method, family := range hashlibMethodAlgorithms {
		if strings.Contains(argsText, "hashlib."+method) {
			return family, types.ConfidenceHigh
		}
	}

	// Check for string literal hash names
	for _, hashName := range []string{"sha256", "sha384", "sha512", "sha1", "md5"} {
		if strings.Contains(argsText, `"`+hashName+`"`) || strings.Contains(argsText, `'`+hashName+`'`) {
			family, ok := hashlibNewAlgorithms[hashName]
			if ok {
				return family, types.ConfidenceHigh
			}
		}
	}

	// Try to resolve digestmod keyword argument
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil || child.Type() != "keyword_argument" {
			continue
		}
		nameNode := child.ChildByFieldName("name")
		valueNode := child.ChildByFieldName("value")
		if nameNode == nil || valueNode == nil {
			continue
		}
		if nameNode.Content(content) == "digestmod" {
			if valueNode.Type() == "identifier" {
				resolved, ok := cp.Resolve(valueNode.Content(content))
				if ok {
					return resolved, types.ConfidenceMedium
				}
			}
		}
	}

	return "unknown", types.ConfidenceLow
}

// hashSeverity returns the severity for a hash algorithm.
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

// buildCipherName creates a human-readable cipher name like "AES-CBC".
func buildCipherName(algoClass, mode string) string {
	name := algoClass
	if mode != "" {
		name = fmt.Sprintf("%s-%s", algoClass, strings.ToUpper(mode))
	}
	return name
}

// ---------------------------------------------------------------------------
// PKCS1v15 padding detection
// ---------------------------------------------------------------------------

func (s *PythonScanner) detectPKCS1v15(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match: padding.PKCS1v15() or PKCS1v15()
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @attr)
		(#eq? @obj "padding")
		(#eq? @attr "PKCS1v15"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var attrNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 1 { // @attr
				attrNode = capture.Node
			}
		}
		if attrNode == nil {
			continue
		}

		callNode := attrNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = attrNode
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "RSA-PKCS1v15",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "pke",
				AlgorithmFamily: "rsa",
				Padding:         "pkcs1v15",
				CryptoFunctions: []string{"encrypt"},
			},
			Description: "RSA PKCS1v15 padding is vulnerable to padding oracle attacks — use OAEP instead",
			RuleID:      "cbom-python-cryptography-pkcs1v15",
			Pass:        1,
		})
	}

	// Also match direct PKCS1v15() call (without module prefix)
	queryStr2 := `(call
		function: (identifier) @fn
		(#eq? @fn "PKCS1v15"))`

	matches2, err := scanner.QueryMatches(root, queryStr2, s.lang, content)
	if err != nil {
		return findings
	}

	for _, match := range matches2 {
		var fnNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 0 {
				fnNode = capture.Node
			}
		}
		if fnNode == nil {
			continue
		}

		callNode := fnNode.Parent()
		if callNode == nil {
			callNode = fnNode
		}

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "RSA-PKCS1v15",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "pke",
				AlgorithmFamily: "rsa",
				Padding:         "pkcs1v15",
				CryptoFunctions: []string{"encrypt"},
			},
			Description: "RSA PKCS1v15 padding is vulnerable to padding oracle attacks — use OAEP instead",
			RuleID:      "cbom-python-cryptography-pkcs1v15",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// F10: Fernet / MultiFernet detection
// ---------------------------------------------------------------------------

func (s *PythonScanner) detectFernet(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match: Fernet(key) or MultiFernet(...)
	for _, fnName := range []string{"Fernet", "MultiFernet"} {
		queryStr := fmt.Sprintf(`(call
			function: (identifier) @fn
			(#eq? @fn "%s"))`, fnName)

		matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
		if err != nil {
			continue
		}

		for _, match := range matches {
			var fnNode *sitter.Node
			for _, capture := range match.Captures {
				if capture.Index == 0 {
					fnNode = capture.Node
				}
			}
			if fnNode == nil {
				continue
			}

			callNode := fnNode.Parent()
			if callNode == nil {
				callNode = fnNode
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       fnName,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "fernet",
					CryptoFunctions: []string{"encrypt", "decrypt"},
				},
				Description: fmt.Sprintf("%s symmetric encryption via cryptography library", fnName),
				RuleID:      fmt.Sprintf("cbom-python-cryptography-%s", strings.ToLower(fnName)),
				Pass:        1,
			})
		}
	}

	// Match: Fernet.generate_key()
	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		(#eq? @obj "Fernet")
		(#eq? @method "generate_key"))`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err == nil {
		for _, match := range matches {
			var methodNode *sitter.Node
			for _, capture := range match.Captures {
				if capture.Index == 1 {
					methodNode = capture.Node
				}
			}
			if methodNode == nil {
				continue
			}

			callNode := methodNode.Parent()
			if callNode != nil {
				callNode = callNode.Parent()
			}
			if callNode == nil {
				callNode = methodNode
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "Fernet",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "fernet",
					CryptoFunctions: []string{"generate"},
				},
				Description: "Fernet key generation via cryptography library",
				RuleID:      "cbom-python-cryptography-fernet-generate-key",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// F11: CMAC and Poly1305 detection
// ---------------------------------------------------------------------------

func (s *PythonScanner) detectCryptoMACs(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Match CMAC(...) calls
	cmacQuery := `(call
		function: (identifier) @fn
		arguments: (argument_list) @args
		(#eq? @fn "CMAC"))`

	cmacMatches, err := scanner.QueryMatches(root, cmacQuery, s.lang, content)
	if err == nil {
		for _, match := range cmacMatches {
			var fnNode, argsNode *sitter.Node
			for _, capture := range match.Captures {
				switch capture.Index {
				case 0:
					fnNode = capture.Node
				case 1:
					argsNode = capture.Node
				}
			}
			if fnNode == nil {
				continue
			}

			callNode := fnNode.Parent()
			if callNode == nil {
				callNode = fnNode
			}

			// Extract inner algorithm from arguments
			algoName := "CMAC"
			if argsNode != nil {
				argsText := scanner.NodeText(argsNode, content)
				if strings.Contains(argsText, "algorithms.AES") {
					algoName = "AES-CMAC"
				} else if strings.Contains(argsText, "algorithms.TripleDES") {
					algoName = "3DES-CMAC"
				}
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       algoName,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "mac",
					AlgorithmFamily: strings.ToLower(algoName),
					CryptoFunctions: []string{"mac"},
				},
				Description: fmt.Sprintf("%s message authentication code via cryptography library", algoName),
				RuleID:      "cbom-python-cryptography-cmac",
				Pass:        1,
			})
		}
	}

	// Match Poly1305(...) calls
	polyQuery := `(call
		function: (identifier) @fn
		(#eq? @fn "Poly1305"))`

	polyMatches, err := scanner.QueryMatches(root, polyQuery, s.lang, content)
	if err == nil {
		for _, match := range polyMatches {
			var fnNode *sitter.Node
			for _, capture := range match.Captures {
				if capture.Index == 0 {
					fnNode = capture.Node
				}
			}
			if fnNode == nil {
				continue
			}

			callNode := fnNode.Parent()
			if callNode == nil {
				callNode = fnNode
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "Poly1305",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "mac",
					AlgorithmFamily: "poly1305",
					CryptoFunctions: []string{"mac"},
				},
				Description: "Poly1305 message authentication code via cryptography library",
				RuleID:      "cbom-python-cryptography-poly1305",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Tier-3 quantum families: BLS + Schnorr (issue #33)
// ---------------------------------------------------------------------------

// detectBLSPython detects py_ecc.bls / blspy usage such as
// `bls.Sign(sk, msg)` or `G2ProofOfPossession.Aggregate(sigs)` when the
// receiver name was imported from a BLS module.
func (s *PythonScanner) detectBLSPython(root *sitter.Node, path string, content []byte) []types.Finding {
	isBLSModule := func(m string) bool {
		return strings.HasPrefix(m, "py_ecc.bls") || m == "py_ecc" ||
			strings.HasPrefix(m, "blspy") || strings.HasPrefix(m, "blst")
	}
	imported := collectImportedNames(root, content, s.lang, isBLSModule)
	// collectImportedNames records the original symbol; also capture aliases,
	// since the common BLS pattern is
	// `from py_ecc.bls import G2ProofOfPossession as bls`.
	for alias := range collectImportAliases(root, content, s.lang, isBLSModule) {
		imported[alias] = true
	}
	if len(imported) == 0 {
		return nil
	}

	var findings []types.Finding

	queryStr := `(call
		function: (attribute
			object: (identifier) @obj
			attribute: (identifier) @method)
		arguments: (argument_list) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var objNode, methodNode *sitter.Node
		for _, capture := range match.Captures {
			switch capture.Index {
			case 0:
				objNode = capture.Node
			case 1:
				methodNode = capture.Node
			}
		}
		if objNode == nil || methodNode == nil {
			continue
		}
		if !imported[scanner.NodeText(objNode, content)] {
			continue
		}
		fn, ok := blsSignMethods[scanner.NodeText(methodNode, content)]
		if !ok {
			continue
		}

		callNode := objNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = objNode
		}

		qi := GetQuantumInfo("bls")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "BLS12-381",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "signature",
				AlgorithmFamily:  "bls",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{fn},
			},
			Description: fmt.Sprintf("BLS12-381 pairing-based signature via %s.%s() — quantum-vulnerable",
				scanner.NodeText(objNode, content), scanner.NodeText(methodNode, content)),
			RuleID: "cbom-python-bls-" + strings.ToLower(scanner.NodeText(methodNode, content)),
			Pass:   1,
		})
	}

	return findings
}

// detectSchnorrPython detects coincurve / secp256k1 Schnorr (BIP-340) usage.
// The method names sign_schnorr / verify_schnorr are coincurve-specific and
// only flagged when coincurve or secp256k1 is imported (zero-FP discipline).
func (s *PythonScanner) detectSchnorrPython(root *sitter.Node, path string, content []byte) []types.Finding {
	imported := collectImportedNames(root, content, s.lang, func(m string) bool {
		return m == "coincurve" || strings.HasPrefix(m, "coincurve") ||
			m == "secp256k1" || strings.HasPrefix(m, "secp256k1")
	})
	// Also accept `import coincurve` (module import, not from-import).
	if len(imported) == 0 && !pythonHasPlainImport(root, content, s.lang, "coincurve", "secp256k1") {
		return nil
	}

	var findings []types.Finding

	// Match any `.sign_schnorr(...)` / `.verify_schnorr(...)` call.
	queryStr := `(call
		function: (attribute
			attribute: (identifier) @method)
		arguments: (argument_list) @args)`

	matches, err := scanner.QueryMatches(root, queryStr, s.lang, content)
	if err != nil {
		return nil
	}

	for _, match := range matches {
		var methodNode *sitter.Node
		for _, capture := range match.Captures {
			if capture.Index == 0 {
				methodNode = capture.Node
			}
		}
		if methodNode == nil {
			continue
		}
		methodName := scanner.NodeText(methodNode, content)
		var fn string
		switch methodName {
		case "sign_schnorr":
			fn = "sign"
		case "verify_schnorr":
			fn = "verify"
		default:
			continue
		}

		callNode := methodNode.Parent()
		if callNode != nil {
			callNode = callNode.Parent()
		}
		if callNode == nil {
			callNode = methodNode
		}

		qi := GetQuantumInfo("schnorr")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "Schnorr",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "signature",
				AlgorithmFamily:  "schnorr",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{fn},
			},
			Description: fmt.Sprintf("Schnorr (BIP-340) signature via %s() — quantum-vulnerable", methodName),
			RuleID:      "cbom-python-schnorr-" + fn,
			Pass:        1,
		})
	}

	return findings
}

// pythonHasPlainImport reports whether the file contains `import <mod>` (or a
// dotted import beginning with <mod>) for any of the supplied module names.
func pythonHasPlainImport(root *sitter.Node, content []byte, lang *sitter.Language, mods ...string) bool {
	queryStr := `(import_statement (dotted_name) @mod)`
	matches, err := scanner.QueryMatches(root, queryStr, lang, content)
	if err != nil {
		return false
	}
	for _, match := range matches {
		for _, capture := range match.Captures {
			name := scanner.NodeText(capture.Node, content)
			for _, m := range mods {
				if name == m || strings.HasPrefix(name, m+".") {
					return true
				}
			}
		}
	}
	return false
}
