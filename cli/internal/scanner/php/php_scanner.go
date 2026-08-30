// Package php detects cryptographic API usage in PHP source files.
//
// PHP cryptographic operations are primarily function-call based, using the
// openssl_*, hash_*, password_*, sodium_*, and mcrypt_* function families.
// The scanner uses tree-sitter's PHP grammar to parse source files and match
// function call patterns, with constant propagation for algorithm arguments
// passed via variables.
package php

import (
	"fmt"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	phpLang "github.com/smacker/go-tree-sitter/php"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/astrules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/keysize"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// PHPScanner detects cryptographic API usage in PHP source files.
type PHPScanner struct {
	lang *sitter.Language
}

// New creates a new PHPScanner instance.
func New() *PHPScanner {
	return &PHPScanner{
		lang: phpLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *PHPScanner) Name() string {
	return "php"
}

// Extensions returns the file extensions this scanner handles.
func (s *PHPScanner) Extensions() []string {
	return []string{".php"}
}

// ScanFile scans a single PHP file's content and returns cryptographic findings.
func (s *PHPScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
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

	// Detect openssl_* function calls
	findings = append(findings, s.detectOpenSSL(root, path, content, cp)...)

	// Detect hash(), hash_hmac(), hash_pbkdf2() calls
	findings = append(findings, s.detectHash(root, path, content, cp)...)

	// Detect password_hash(), password_verify() calls
	findings = append(findings, s.detectPasswordHash(root, path, content, cp)...)

	// Detect sodium_* function calls
	findings = append(findings, s.detectSodium(root, path, content)...)

	// Detect mcrypt_* function calls (deprecated)
	findings = append(findings, s.detectMcrypt(root, path, content, cp)...)

	return scanner.AnnotateFindings(findings), nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// openssl detection
// ---------------------------------------------------------------------------

// The PHP Pass-1 detection tables below are DATA, loaded from the embedded
// scanner/ast-rules/php.yml at init() and replaceable at scan time via
// --ast-rules-dir (astrules.LoadPHP). Only the tables (token -> crypto
// semantics) are external; the tree-sitter query machinery stays in Go. See
// docs/ast-rules-external-design.md. The local struct types preserve the exact
// field names the detect sites already use, so wiring them from data required
// no change at the lookup sites.

type opensslFuncT struct {
	primitive    string
	cryptoFuncs  []string
	methodArgIdx int
	isKeyGen     bool
}

type opensslMethodT struct {
	family string
	mode   string
	name   string
}

type hashAlgoT struct {
	family string
	name   string
}

type passwordAlgoT struct {
	family string
	name   string
}

type sodiumFuncT struct {
	family    string
	name      string
	primitive string
	funcs     []string
}

type mcryptFuncT struct {
	funcs []string
}

var (
	// opensslFuncMap maps openssl_* function names to their crypto operation details.
	opensslFuncMap map[string]opensslFuncT
	// opensslMethodMap maps PHP openssl cipher method strings to algorithm details.
	opensslMethodMap map[string]opensslMethodT
	// hashAlgoMap maps PHP hash algorithm names to algorithm families and human-readable names.
	hashAlgoMap map[string]hashAlgoT
	// passwordAlgoMap maps PHP PASSWORD_* constants to algorithm details.
	passwordAlgoMap map[string]passwordAlgoT
	// sodiumFuncMap maps sodium_* function names to crypto details.
	sodiumFuncMap map[string]sodiumFuncT
	// mcryptFuncMap maps mcrypt_* function names to crypto details.
	mcryptFuncMap map[string]mcryptFuncT
)

func init() {
	applyPHPTables(astrules.MustLoadPHPEmbedded())
}

// applyPHPTables (re)populates the package-level detection tables from a loaded
// astrules.PHPTables. Called at init with the embedded set and again by
// ApplyExternalRules when --ast-rules-dir is given.
func applyPHPTables(t *astrules.PHPTables) {
	of := make(map[string]opensslFuncT, len(t.OpenSSLFuncs))
	for _, r := range t.OpenSSLFuncs {
		of[r.Func] = opensslFuncT{primitive: r.Primitive, cryptoFuncs: r.CryptoFuncs, methodArgIdx: r.MethodArgIdx, isKeyGen: r.IsKeyGen}
	}
	opensslFuncMap = of

	om := make(map[string]opensslMethodT, len(t.OpenSSLMethods))
	for _, r := range t.OpenSSLMethods {
		om[r.Method] = opensslMethodT{family: r.Family, mode: r.Mode, name: r.Name}
	}
	opensslMethodMap = om

	ha := make(map[string]hashAlgoT, len(t.HashAlgos))
	for _, r := range t.HashAlgos {
		ha[r.Algo] = hashAlgoT{family: r.Family, name: r.Name}
	}
	hashAlgoMap = ha

	pa := make(map[string]passwordAlgoT, len(t.PasswordAlgos))
	for _, r := range t.PasswordAlgos {
		pa[r.Const] = passwordAlgoT{family: r.Family, name: r.Name}
	}
	passwordAlgoMap = pa

	sf := make(map[string]sodiumFuncT, len(t.SodiumFuncs))
	for _, r := range t.SodiumFuncs {
		sf[r.Func] = sodiumFuncT{family: r.Family, name: r.Name, primitive: r.Primitive, funcs: r.Funcs}
	}
	sodiumFuncMap = sf

	mf := make(map[string]mcryptFuncT, len(t.McryptFuncs))
	for _, r := range t.McryptFuncs {
		mf[r.Func] = mcryptFuncT{funcs: r.Funcs}
	}
	mcryptFuncMap = mf
}

// ApplyExternalRules replaces the active PHP Pass-1 tables from an external
// --ast-rules-dir. When dir is empty, or has no php.yml, the embedded tables
// are restored (per-language fallback). Returns an error only when a present
// php.yml is malformed.
func ApplyExternalRules(dir string) error {
	t, err := astrules.LoadPHP(dir)
	if err != nil {
		return err
	}
	applyPHPTables(t)
	return nil
}

func (s *PHPScanner) detectOpenSSL(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// Walk entire AST looking for function_call_expression nodes
	s.walkForFunctionCalls(root, content, func(fnName string, callNode *sitter.Node, argsNode *sitter.Node) {
		info, ok := opensslFuncMap[fnName]
		if !ok {
			return
		}

		if info.isKeyGen {
			// openssl_pkey_new — detect from config array (best effort)
			finding := s.handleOpenSSLPkeyNew(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
			return
		}

		if fnName == "openssl_sign" {
			// openssl_sign uses the 4th argument for algorithm constant
			finding := s.handleOpenSSLSign(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
			return
		}

		// For encrypt/decrypt/seal, resolve the method argument
		if info.methodArgIdx < 0 {
			return
		}

		method, confidence := resolveNthArg(argsNode, info.methodArgIdx, content, cp)
		if method == "" {
			// Still emit a finding with unknown algorithm
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       fmt.Sprintf("OpenSSL %s (unknown algorithm)", fnName),
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceLow,
				Properties: types.CryptoProperties{
					Primitive:       info.primitive,
					CryptoFunctions: info.cryptoFuncs,
				},
				Description: fmt.Sprintf("OpenSSL %s() with unresolved algorithm", fnName),
				RuleID:      fmt.Sprintf("cbom-php-%s-unknown", fnName),
				Pass:        1,
			})
			return
		}

		normalizedMethod := strings.ToLower(method)
		algoInfo, known := opensslMethodMap[normalizedMethod]
		if !known {
			// Unrecognized method — still emit finding
			algoInfo = opensslMethodT{family: normalizedMethod, mode: "", name: strings.ToUpper(method)}
		}

		qi := quantum.GetInfo(algoInfo.family)
		severity := cipherSeverity(algoInfo.family, algoInfo.mode)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       algoInfo.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: confidence,
			Properties: types.CryptoProperties{
				Primitive:        info.primitive,
				AlgorithmFamily:  algoInfo.family,
				Mode:             algoInfo.mode,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  info.cryptoFuncs,
			},
			Description: fmt.Sprintf("OpenSSL %s() using %s", fnName, algoInfo.name),
			RuleID:      fmt.Sprintf("cbom-php-%s-%s", fnName, sanitizeRuleID(normalizedMethod)),
			Pass:        1,
		})
	})

	return findings
}

func (s *PHPScanner) handleOpenSSLPkeyNew(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	// openssl_pkey_new($config) — try to detect key type from config array
	// Best-effort: look for 'private_key_type' or 'private_key_bits' in the argument text
	name := "OpenSSL Key Generation"
	family := "rsa" // default assumption for openssl_pkey_new
	keySize := 0
	severity := types.SeverityInfo
	confidence := types.ConfidenceMedium

	if argsNode != nil {
		argsText := argsNode.Content(content)
		argsLower := strings.ToLower(argsText)
		if ks := keysize.ParsePHPPrivateKeyBits(argsText); ks > 0 {
			keySize = ks
		}
		if strings.Contains(argsLower, "openssl_keytype_ec") {
			family = "ec"
			name = "EC Key Generation"
		} else if strings.Contains(argsLower, "openssl_keytype_dsa") {
			family = "dsa"
			name = "DSA Key Generation"
		} else if strings.Contains(argsLower, "openssl_keytype_dh") {
			family = "dh"
			name = "DH Key Generation"
		} else if strings.Contains(argsLower, "openssl_keytype_rsa") {
			family = "rsa"
			name = "RSA Key Generation"
		}
	}

	if keySize > 0 && family == "rsa" {
		name = fmt.Sprintf("RSA-%d", keySize)
	}

	qi := quantum.GetInfo(family)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "pke",
			AlgorithmFamily:  family,
			KeySize:          keySize,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"generate"},
		},
		Description: fmt.Sprintf("Key generation via openssl_pkey_new() — %s", family),
		RuleID:      fmt.Sprintf("cbom-php-openssl_pkey_new-%s", family),
		Pass:        1,
	}
}

func (s *PHPScanner) handleOpenSSLSign(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	// openssl_sign($data, &$signature, $key, $algorithm)
	// The 4th argument (index 3) is the algorithm constant (e.g. OPENSSL_ALGO_SHA256)
	name := "OpenSSL Signature"
	family := "rsa"
	hashAlgo := "unknown"
	confidence := types.ConfidenceMedium

	if argsNode != nil {
		argsText := argsNode.Content(content)
		hashAlgo, family = resolveOpenSSLSignAlgo(argsText)
		if hashAlgo != "unknown" {
			name = fmt.Sprintf("OpenSSL Sign (%s)", strings.ToUpper(hashAlgo))
			confidence = types.ConfidenceHigh
		}
	}

	qi := quantum.GetInfo(family)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "signature",
			AlgorithmFamily:  family,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"sign"},
		},
		Description: fmt.Sprintf("Digital signature via openssl_sign() with %s", hashAlgo),
		RuleID:      "cbom-php-openssl_sign-signature",
		Pass:        1,
	}
}

// resolveOpenSSLSignAlgo extracts the signature algorithm from openssl_sign arguments text.
func resolveOpenSSLSignAlgo(argsText string) (hashAlgo string, family string) {
	upper := strings.ToUpper(argsText)
	algoMap := map[string]struct {
		hash   string
		family string
	}{
		"OPENSSL_ALGO_SHA1":   {hash: "sha1", family: "rsa"},
		"OPENSSL_ALGO_SHA256": {hash: "sha-256", family: "rsa"},
		"OPENSSL_ALGO_SHA384": {hash: "sha-384", family: "rsa"},
		"OPENSSL_ALGO_SHA512": {hash: "sha-512", family: "rsa"},
		"OPENSSL_ALGO_MD5":    {hash: "md5", family: "rsa"},
		"OPENSSL_ALGO_MD4":    {hash: "md4", family: "rsa"},
		"OPENSSL_ALGO_DSS1":   {hash: "sha1", family: "dsa"},
	}
	for constant, info := range algoMap {
		if strings.Contains(upper, constant) {
			return info.hash, info.family
		}
	}
	return "unknown", "rsa"
}

// ---------------------------------------------------------------------------
// hash / hash_hmac / hash_pbkdf2 detection
// ---------------------------------------------------------------------------

func (s *PHPScanner) detectHash(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	s.walkForFunctionCalls(root, content, func(fnName string, callNode *sitter.Node, argsNode *sitter.Node) {
		switch fnName {
		case "hash":
			finding := s.handleHashCall(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "hash_hmac":
			finding := s.handleHashHMAC(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "hash_pbkdf2":
			finding := s.handleHashPBKDF2(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	})

	return findings
}

func (s *PHPScanner) handleHashCall(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	algoName, confidence := resolveNthArg(argsNode, 0, content, cp)
	if algoName == "" {
		return nil
	}

	normalizedAlgo := strings.ToLower(algoName)
	info, ok := hashAlgoMap[normalizedAlgo]
	if !ok {
		info = hashAlgoT{family: normalizedAlgo, name: algoName}
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
		Description: fmt.Sprintf("Hash function %s via hash()", info.name),
		RuleID:      fmt.Sprintf("cbom-php-hash-%s", sanitizeRuleID(normalizedAlgo)),
		Pass:        1,
	}
}

func (s *PHPScanner) handleHashHMAC(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	algoName, confidence := resolveNthArg(argsNode, 0, content, cp)
	if algoName == "" {
		algoName = "unknown"
		confidence = types.ConfidenceLow
	}

	normalizedAlgo := strings.ToLower(algoName)
	info, ok := hashAlgoMap[normalizedAlgo]
	if !ok {
		info = hashAlgoT{family: normalizedAlgo, name: algoName}
	}

	name := fmt.Sprintf("HMAC-%s", info.name)
	qi := quantum.GetInfo(info.family)

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "mac",
			AlgorithmFamily:  info.family,
			QuantumStatus:    qi.Status,
			NistQuantumLevel: qi.NistLevel,
			CryptoFunctions:  []string{"mac"},
		},
		Description: fmt.Sprintf("HMAC with %s via hash_hmac()", info.name),
		RuleID:      fmt.Sprintf("cbom-php-hash_hmac-%s", sanitizeRuleID(normalizedAlgo)),
		Pass:        1,
	}
}

func (s *PHPScanner) handleHashPBKDF2(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	if argsNode == nil {
		return nil
	}

	algoName, confidence := resolveNthArg(argsNode, 0, content, cp)
	if algoName == "" {
		algoName = "unknown"
		confidence = types.ConfidenceLow
	}

	normalizedAlgo := strings.ToLower(algoName)
	info, ok := hashAlgoMap[normalizedAlgo]
	if !ok {
		info = hashAlgoT{family: normalizedAlgo, name: algoName}
	}

	name := fmt.Sprintf("PBKDF2-%s", info.name)
	severity := types.SeverityInfo

	// Check iteration count (4th argument, index 3)
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
			Primitive:       "kdf",
			AlgorithmFamily: "pbkdf2",
			CryptoFunctions: []string{"derive"},
		},
		Description: fmt.Sprintf("Key derivation using PBKDF2 with %s via hash_pbkdf2()", info.name),
		RuleID:      fmt.Sprintf("cbom-php-hash_pbkdf2-%s", sanitizeRuleID(normalizedAlgo)),
		Pass:        1,
	}
}

// ---------------------------------------------------------------------------
// password_hash / password_verify detection
// ---------------------------------------------------------------------------

func (s *PHPScanner) detectPasswordHash(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	s.walkForFunctionCalls(root, content, func(fnName string, callNode *sitter.Node, argsNode *sitter.Node) {
		switch fnName {
		case "password_hash":
			finding := s.handlePasswordHash(callNode, argsNode, path, content, cp)
			if finding != nil {
				findings = append(findings, *finding)
			}
		case "password_verify":
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "password_verify",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "kdf",
					CryptoFunctions: []string{"verify"},
				},
				Description: "Password verification via password_verify()",
				RuleID:      "cbom-php-password_verify-verify",
				Pass:        1,
			})
		}
	})

	return findings
}

func (s *PHPScanner) handlePasswordHash(callNode, argsNode *sitter.Node, path string, content []byte, cp *ConstPropagator) *types.Finding {
	name := "password_hash (unknown algorithm)"
	family := "bcrypt"
	confidence := types.ConfidenceLow

	if argsNode != nil {
		argsText := argsNode.Content(content)
		for constant, info := range passwordAlgoMap {
			if strings.Contains(argsText, constant) {
				name = info.name
				family = info.family
				confidence = types.ConfidenceHigh
				break
			}
		}
	}

	return &types.Finding{
		ID:         nextFindingID(),
		AssetType:  types.AssetAlgorithm,
		Name:       name,
		Location:   scanner.NodeLocation(callNode, path, content),
		Severity:   types.SeverityInfo,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:       "kdf",
			AlgorithmFamily: family,
			CryptoFunctions: []string{"hash"},
		},
		Description: fmt.Sprintf("Password hashing via password_hash() using %s", family),
		RuleID:      fmt.Sprintf("cbom-php-password_hash-%s", family),
		Pass:        1,
	}
}

// ---------------------------------------------------------------------------
// sodium detection
// ---------------------------------------------------------------------------

func (s *PHPScanner) detectSodium(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	s.walkForFunctionCalls(root, content, func(fnName string, callNode *sitter.Node, _ *sitter.Node) {
		info, ok := sodiumFuncMap[fnName]
		if !ok {
			return
		}

		qi := quantum.GetInfo(info.family)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       info.name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        info.primitive,
				AlgorithmFamily:  info.family,
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  info.funcs,
			},
			Description: fmt.Sprintf("Sodium %s via %s()", info.name, fnName),
			RuleID:      fmt.Sprintf("cbom-php-%s-%s", fnName, sanitizeRuleID(info.family)),
			Pass:        1,
		})
	})

	return findings
}

// ---------------------------------------------------------------------------
// mcrypt detection (deprecated)
// ---------------------------------------------------------------------------

func (s *PHPScanner) detectMcrypt(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	s.walkForFunctionCalls(root, content, func(fnName string, callNode *sitter.Node, argsNode *sitter.Node) {
		info, ok := mcryptFuncMap[fnName]
		if !ok {
			return
		}

		// Try to resolve the cipher name from first argument
		cipherName := "unknown"
		if argsNode != nil {
			resolved, _ := resolveNthArg(argsNode, 0, content, cp)
			if resolved != "" {
				cipherName = resolved
			}
		}

		name := fmt.Sprintf("mcrypt (%s)", cipherName)

		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       name,
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityHigh,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "block-cipher",
				CryptoFunctions: info.funcs,
			},
			Description: fmt.Sprintf("Deprecated mcrypt function %s() — removed in PHP 7.2", fnName),
			RuleID:      fmt.Sprintf("cbom-php-%s-deprecated", fnName),
			Pass:        1,
		})
	})

	return findings
}

// ---------------------------------------------------------------------------
// AST walking helpers
// ---------------------------------------------------------------------------

// walkForFunctionCalls walks the AST and calls the callback for each function_call_expression node.
// The callback receives the function name, the call node, and the arguments node.
func (s *PHPScanner) walkForFunctionCalls(node *sitter.Node, content []byte, callback func(fnName string, callNode *sitter.Node, argsNode *sitter.Node)) {
	if node == nil {
		return
	}
	s.walkForFunctionCallsRecursive(node, content, callback)
}

func (s *PHPScanner) walkForFunctionCallsRecursive(node *sitter.Node, content []byte, callback func(string, *sitter.Node, *sitter.Node)) {
	if node == nil {
		return
	}

	if node.Type() == "function_call_expression" {
		fnNode := node.ChildByFieldName("function")
		argsNode := node.ChildByFieldName("arguments")

		if fnNode != nil {
			fnName := fnNode.Content(content)
			// Only process simple function names (not method calls or namespaced calls with ->)
			if !strings.Contains(fnName, "->") && !strings.Contains(fnName, "::") {
				// Strip namespace prefix for matching (e.g. \openssl_encrypt -> openssl_encrypt)
				fnName = strings.TrimLeft(fnName, "\\")
				callback(fnName, node, argsNode)
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			s.walkForFunctionCallsRecursive(child, content, callback)
		}
	}
}

// ---------------------------------------------------------------------------
// Argument resolution helpers
// ---------------------------------------------------------------------------

// resolveNthArg resolves the nth positional argument (0-indexed) from a PHP
// argument list node. Returns the resolved value and the confidence level.
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
		// Skip delimiters
		if nodeType == "(" || nodeType == ")" || nodeType == "," {
			continue
		}

		// Handle argument node wrapping
		argChild := child
		if nodeType == "argument" {
			// In PHP grammar, arguments can be wrapped in an "argument" node
			if child.ChildCount() > 0 {
				// Use the actual value child
				for j := 0; j < int(child.ChildCount()); j++ {
					c := child.Child(j)
					if c != nil && c.Type() != "name" {
						argChild = c
						break
					}
				}
			}
		}

		if posIdx == n {
			return resolveNodeValue(argChild, content, cp)
		}
		posIdx++
	}

	return "", types.ConfidenceLow
}

// resolveNthArgInt resolves the nth positional argument to an integer value.
func resolveNthArgInt(argsNode *sitter.Node, n int, content []byte, cp *ConstPropagator) int {
	val, _ := resolveNthArg(argsNode, n, content, cp)
	if val == "" {
		return 0
	}
	// Try to parse as integer
	var result int
	fmt.Sscanf(val, "%d", &result)
	return result
}

// resolveNodeValue extracts a value from a tree-sitter node.
func resolveNodeValue(node *sitter.Node, content []byte, cp *ConstPropagator) (string, types.Confidence) {
	if node == nil {
		return "", types.ConfidenceLow
	}

	switch node.Type() {
	case "string", "encapsed_string":
		raw := node.Content(content)
		return unquotePHPString(raw), types.ConfidenceHigh
	case "integer":
		return node.Content(content), types.ConfidenceHigh
	case "variable_name":
		varName := strings.TrimPrefix(node.Content(content), "$")
		if val, ok := cp.Resolve(varName); ok {
			return val, types.ConfidenceMedium
		}
		return "", types.ConfidenceLow
	default:
		// Try to handle as text — might be a variable reference or constant
		text := node.Content(content)
		if strings.HasPrefix(text, "$") {
			varName := strings.TrimPrefix(text, "$")
			if val, ok := cp.Resolve(varName); ok {
				return val, types.ConfidenceMedium
			}
			return "", types.ConfidenceLow
		}
		// Could be a PHP constant like PASSWORD_BCRYPT
		if text != "" && text != "(" && text != ")" && text != "," {
			return text, types.ConfidenceLow
		}
		return "", types.ConfidenceLow
	}
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// hashSeverity returns the severity for a hash algorithm family.
func hashSeverity(algoFamily string) types.Severity {
	switch algoFamily {
	case "md5", "md4", "sha1":
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

// unquotePHPString removes surrounding quotes from a PHP string literal.
// Handles single quotes and double quotes.
func unquotePHPString(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	// Handle heredoc/nowdoc (<<<) — just return as-is
	if strings.HasPrefix(raw, "<<<") {
		return raw
	}

	// Single or double quotes
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
