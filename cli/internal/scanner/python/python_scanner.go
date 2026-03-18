package python

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	python "github.com/smacker/go-tree-sitter/python"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
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

	// Detect hmac module usage
	hmacFindings := s.detectHMAC(root, path, content, cp)
	findings = append(findings, hmacFindings...)

	return findings, nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// hashlib detection
// ---------------------------------------------------------------------------

// hashlibMethodAlgorithms maps hashlib method names to algorithm family names.
var hashlibMethodAlgorithms = map[string]string{
	"md5":      "md5",
	"sha1":     "sha1",
	"sha224":   "sha-256", // SHA-224 is a truncated SHA-256
	"sha256":   "sha-256",
	"sha384":   "sha-384",
	"sha512":   "sha-512",
	"sha3_256": "sha3-256",
	"sha3_384": "sha3-384",
	"sha3_512": "sha3-512",
	"blake2b":  "blake2b",
	"blake2s":  "blake2s",
}

// hashlibMethodNames maps hashlib method names to human-readable names.
var hashlibMethodNames = map[string]string{
	"md5":      "MD5",
	"sha1":     "SHA-1",
	"sha224":   "SHA-224",
	"sha256":   "SHA-256",
	"sha384":   "SHA-384",
	"sha512":   "SHA-512",
	"sha3_256": "SHA3-256",
	"sha3_384": "SHA3-384",
	"sha3_512": "SHA3-512",
	"blake2b":  "BLAKE2b",
	"blake2s":  "BLAKE2s",
}

// hashlibNewAlgorithms maps string arguments to hashlib.new() to algorithm families.
var hashlibNewAlgorithms = map[string]string{
	"md5":      "md5",
	"sha1":     "sha1",
	"sha224":   "sha-256",
	"sha256":   "sha-256",
	"sha384":   "sha-384",
	"sha512":   "sha-512",
	"sha3_256": "sha3-256",
	"sha3_384": "sha3-384",
	"sha3_512": "sha3-512",
	"blake2b":  "blake2b",
	"blake2s":  "blake2s",
}

// hashlibNewNames maps string arguments to hashlib.new() to human-readable names.
var hashlibNewNames = map[string]string{
	"md5":      "MD5",
	"sha1":     "SHA-1",
	"sha224":   "SHA-224",
	"sha256":   "SHA-256",
	"sha384":   "SHA-384",
	"sha512":   "SHA-512",
	"sha3_256": "SHA3-256",
	"sha3_384": "SHA3-384",
	"sha3_512": "SHA3-512",
	"blake2b":  "BLAKE2b",
	"blake2s":  "BLAKE2s",
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
					ID:        nextFindingID(),
					AssetType: types.AssetAlgorithm,
					Name:      humanName,
					Location:  scanner.NodeLocation(callNode, path, content),
					Severity:  severity,
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
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      humanName,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  severity,
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
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      name,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  severity,
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

// cipherAlgoMap maps cryptography.hazmat algorithm class names to algorithm families.
var cipherAlgoMap = map[string]struct {
	family    string
	primitive string
}{
	"AES":       {family: "aes", primitive: "block-cipher"},
	"TripleDES": {family: "3des", primitive: "block-cipher"},
	"ChaCha20":  {family: "chacha20", primitive: "stream-cipher"},
	"Camellia":  {family: "camellia", primitive: "block-cipher"},
	"CAST5":     {family: "cast5", primitive: "block-cipher"},
	"SEED":      {family: "seed", primitive: "block-cipher"},
	"Blowfish":  {family: "blowfish", primitive: "block-cipher"},
	"ARC4":      {family: "rc4", primitive: "stream-cipher"},
	"IDEA":      {family: "idea", primitive: "block-cipher"},
}

// cipherModeMap maps mode class names to their lowercase identifiers.
var cipherModeMap = map[string]string{
	"CBC": "cbc",
	"ECB": "ecb",
	"GCM": "gcm",
	"CTR": "ctr",
	"OFB": "ofb",
	"CFB": "cfb",
	"XTS": "xts",
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
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      humanName,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  severity,
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

// cryptoHashMap maps cryptography hash class names to algorithm families.
var cryptoHashMap = map[string]struct {
	family string
	name   string
}{
	"SHA256":   {family: "sha-256", name: "SHA-256"},
	"SHA384":   {family: "sha-384", name: "SHA-384"},
	"SHA512":   {family: "sha-512", name: "SHA-512"},
	"SHA224":   {family: "sha-256", name: "SHA-224"},
	"SHA1":     {family: "sha1", name: "SHA-1"},
	"MD5":      {family: "md5", name: "MD5"},
	"BLAKE2b":  {family: "blake2b", name: "BLAKE2b"},
	"BLAKE2s":  {family: "blake2s", name: "BLAKE2s"},
	"SHA3_256": {family: "sha3-256", name: "SHA3-256"},
	"SHA3_384": {family: "sha3-384", name: "SHA3-384"},
	"SHA3_512": {family: "sha3-512", name: "SHA3-512"},
	"SM3":      {family: "sm3", name: "SM3"},
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
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      info.name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  severity,
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
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      name,
				Location:  scanner.NodeLocation(callNode, path, content),
				Severity:  severity,
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
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      name,
				Location:  scanner.NodeLocation(callNode, path, content),
				Severity:  types.SeverityInfo,
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
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      name,
				Location:  scanner.NodeLocation(callNode, path, content),
				Severity:  types.SeverityInfo,
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

		findings = append(findings, types.Finding{
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "signature",
				AlgorithmFamily:  algoFamily,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"generate"},
			},
			Description: fmt.Sprintf("%s key generation via cryptography library", name),
			RuleID:      fmt.Sprintf("cbom-python-cryptography-%s-generate", algoFamily),
			Pass:        1,
		})
	}

	return findings
}

// kdfMap maps KDF class names to their algorithm families and descriptions.
var kdfMap = map[string]struct {
	family string
	name   string
}{
	"PBKDF2HMAC": {family: "pbkdf2", name: "PBKDF2-HMAC"},
	"HKDF":       {family: "hkdf", name: "HKDF"},
	"HKDFExpand": {family: "hkdf", name: "HKDF-Expand"},
	"Scrypt":     {family: "scrypt", name: "Scrypt"},
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
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      info.name,
				Location:  scanner.NodeLocation(callNode, path, content),
				Severity:  types.SeverityInfo,
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
		}
	}

	return findings
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

// sslProtocolMap maps ssl.PROTOCOL_* constants to protocol info.
var sslProtocolMap = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"PROTOCOL_TLS":      {name: "TLS", version: "", severity: types.SeverityInfo},
	"PROTOCOL_TLS_CLIENT": {name: "TLS", version: "", severity: types.SeverityInfo},
	"PROTOCOL_TLS_SERVER": {name: "TLS", version: "", severity: types.SeverityInfo},
	"PROTOCOL_TLSv1":    {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"PROTOCOL_TLSv1_1":  {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"PROTOCOL_TLSv1_2":  {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"PROTOCOL_SSLv2":    {name: "SSL 2.0", version: "2.0", severity: types.SeverityHigh},
	"PROTOCOL_SSLv3":    {name: "SSL 3.0", version: "3.0", severity: types.SeverityHigh},
	"PROTOCOL_SSLv23":   {name: "SSL/TLS", version: "", severity: types.SeverityInfo},
}

// sslTLSVersionMap maps ssl.TLSVersion.* constants to version info.
var sslTLSVersionMap = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"TLSv1":   {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"TLSv1_1": {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"TLSv1_2": {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"TLSv1_3": {name: "TLS 1.3", version: "1.3", severity: types.SeverityInfo},
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
			ID:        nextFindingID(),
			AssetType: types.AssetProtocol,
			Name:      info.name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  info.severity,
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
			ID:        nextFindingID(),
			AssetType: types.AssetProtocol,
			Name:      info.name,
			Location:  scanner.NodeLocation(attrNode, path, content),
			Severity:  info.severity,
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
			ID:        nextFindingID(),
			AssetType: types.AssetProtocol,
			Name:      "Certificate Validation Disabled",
			Location:  scanner.NodeLocation(node, path, content),
			Severity:  types.SeverityCritical,
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
			ID:        nextFindingID(),
			AssetType: types.AssetProtocol,
			Name:      "ssl.wrap_socket (deprecated)",
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  types.SeverityMedium,
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

// pyCryptoImportMap maps PyCryptodome import names to crypto info.
var pyCryptoImportMap = map[string]struct {
	family    string
	name      string
	primitive string
}{
	"AES":       {family: "aes", name: "AES", primitive: "block-cipher"},
	"DES":       {family: "des", name: "DES", primitive: "block-cipher"},
	"DES3":      {family: "3des", name: "3DES", primitive: "block-cipher"},
	"Blowfish":  {family: "blowfish", name: "Blowfish", primitive: "block-cipher"},
	"ARC4":      {family: "rc4", name: "RC4", primitive: "stream-cipher"},
	"ChaCha20":  {family: "chacha20", name: "ChaCha20", primitive: "stream-cipher"},
	"Salsa20":   {family: "salsa20", name: "Salsa20", primitive: "stream-cipher"},
	"CAST":      {family: "cast5", name: "CAST5", primitive: "block-cipher"},
	"SHA256":    {family: "sha-256", name: "SHA-256", primitive: "hash"},
	"SHA1":      {family: "sha1", name: "SHA-1", primitive: "hash"},
	"SHA512":    {family: "sha-512", name: "SHA-512", primitive: "hash"},
	"SHA384":    {family: "sha-384", name: "SHA-384", primitive: "hash"},
	"MD5":       {family: "md5", name: "MD5", primitive: "hash"},
	"HMAC":      {family: "hmac", name: "HMAC", primitive: "mac"},
	"RSA":       {family: "rsa", name: "RSA", primitive: "pke"},
	"DSA":       {family: "dsa", name: "DSA", primitive: "signature"},
	"ECC":       {family: "ec", name: "EC", primitive: "key-agree"},
}

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
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      info.name,
			Location:  scanner.NodeLocation(stmtNode, path, content),
			Severity:  severity,
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
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  types.SeverityInfo,
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
	}

	return findings
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
