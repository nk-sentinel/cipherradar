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

	return findings, nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// openssl detection
// ---------------------------------------------------------------------------

// opensslFuncMap maps openssl_* function names to their crypto operation details.
var opensslFuncMap = map[string]struct {
	primitive     string
	cryptoFuncs   []string
	methodArgIdx  int  // index of the $method/$algo argument in the arg list (-1 if none)
	isKeyGen      bool // whether this is a key generation function
}{
	"openssl_encrypt":  {primitive: "block-cipher", cryptoFuncs: []string{"encrypt"}, methodArgIdx: 1},
	"openssl_decrypt":  {primitive: "block-cipher", cryptoFuncs: []string{"decrypt"}, methodArgIdx: 1},
	"openssl_sign":     {primitive: "signature", cryptoFuncs: []string{"sign"}, methodArgIdx: -1},
	"openssl_seal":     {primitive: "pke", cryptoFuncs: []string{"encrypt", "seal"}, methodArgIdx: 4},
	"openssl_pkey_new": {primitive: "pke", cryptoFuncs: []string{"generate"}, methodArgIdx: -1, isKeyGen: true},
}

// opensslMethodMap maps PHP openssl cipher method strings to algorithm details.
var opensslMethodMap = map[string]struct {
	family string
	mode   string
	name   string
}{
	"aes-128-cbc":         {family: "aes", mode: "cbc", name: "AES-128-CBC"},
	"aes-192-cbc":         {family: "aes", mode: "cbc", name: "AES-192-CBC"},
	"aes-256-cbc":         {family: "aes", mode: "cbc", name: "AES-256-CBC"},
	"aes-128-ecb":         {family: "aes", mode: "ecb", name: "AES-128-ECB"},
	"aes-192-ecb":         {family: "aes", mode: "ecb", name: "AES-192-ECB"},
	"aes-256-ecb":         {family: "aes", mode: "ecb", name: "AES-256-ECB"},
	"aes-128-gcm":         {family: "aes", mode: "gcm", name: "AES-128-GCM"},
	"aes-192-gcm":         {family: "aes", mode: "gcm", name: "AES-192-GCM"},
	"aes-256-gcm":         {family: "aes", mode: "gcm", name: "AES-256-GCM"},
	"aes-128-ctr":         {family: "aes", mode: "ctr", name: "AES-128-CTR"},
	"aes-256-ctr":         {family: "aes", mode: "ctr", name: "AES-256-CTR"},
	"aes-128-cfb":         {family: "aes", mode: "cfb", name: "AES-128-CFB"},
	"aes-256-cfb":         {family: "aes", mode: "cfb", name: "AES-256-CFB"},
	"aes-128-ofb":         {family: "aes", mode: "ofb", name: "AES-128-OFB"},
	"aes-256-ofb":         {family: "aes", mode: "ofb", name: "AES-256-OFB"},
	"des-cbc":             {family: "des", mode: "cbc", name: "DES-CBC"},
	"des-ecb":             {family: "des", mode: "ecb", name: "DES-ECB"},
	"des-ede3-cbc":        {family: "3des", mode: "cbc", name: "3DES-CBC"},
	"des-ede3":            {family: "3des", mode: "", name: "3DES"},
	"bf-cbc":              {family: "blowfish", mode: "cbc", name: "Blowfish-CBC"},
	"bf-ecb":              {family: "blowfish", mode: "ecb", name: "Blowfish-ECB"},
	"rc4":                 {family: "rc4", mode: "", name: "RC4"},
	"camellia-128-cbc":    {family: "camellia", mode: "cbc", name: "Camellia-128-CBC"},
	"camellia-256-cbc":    {family: "camellia", mode: "cbc", name: "Camellia-256-CBC"},
	"chacha20-poly1305":   {family: "chacha20", mode: "", name: "ChaCha20-Poly1305"},
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
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      fmt.Sprintf("OpenSSL %s (unknown algorithm)", fnName),
				Location:  scanner.NodeLocation(callNode, path, content),
				Severity:  types.SeverityInfo,
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
			algoInfo = struct {
				family string
				mode   string
				name   string
			}{family: normalizedMethod, mode: "", name: strings.ToUpper(method)}
		}

		qi := quantum.GetInfo(algoInfo.family)
		severity := cipherSeverity(algoInfo.family, algoInfo.mode)

		findings = append(findings, types.Finding{
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      algoInfo.name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  severity,
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
	severity := types.SeverityInfo
	confidence := types.ConfidenceMedium

	if argsNode != nil {
		argsText := strings.ToLower(argsNode.Content(content))
		if strings.Contains(argsText, "openssl_keytype_ec") {
			family = "ec"
			name = "EC Key Generation"
		} else if strings.Contains(argsText, "openssl_keytype_dsa") {
			family = "dsa"
			name = "DSA Key Generation"
		} else if strings.Contains(argsText, "openssl_keytype_dh") {
			family = "dh"
			name = "DH Key Generation"
		} else if strings.Contains(argsText, "openssl_keytype_rsa") {
			family = "rsa"
			name = "RSA Key Generation"
		}
	}

	qi := quantum.GetInfo(family)

	return &types.Finding{
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      name,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  severity,
		Confidence: confidence,
		Properties: types.CryptoProperties{
			Primitive:        "pke",
			AlgorithmFamily:  family,
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
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      name,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  types.SeverityInfo,
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

// hashAlgoMap maps PHP hash algorithm names to algorithm families and human-readable names.
var hashAlgoMap = map[string]struct {
	family string
	name   string
}{
	"md5":      {family: "md5", name: "MD5"},
	"md4":      {family: "md4", name: "MD4"},
	"sha1":     {family: "sha1", name: "SHA-1"},
	"sha224":   {family: "sha-256", name: "SHA-224"},
	"sha256":   {family: "sha-256", name: "SHA-256"},
	"sha384":   {family: "sha-384", name: "SHA-384"},
	"sha512":   {family: "sha-512", name: "SHA-512"},
	"sha3-256": {family: "sha3-256", name: "SHA3-256"},
	"sha3-384": {family: "sha3-384", name: "SHA3-384"},
	"sha3-512": {family: "sha3-512", name: "SHA3-512"},
	"ripemd160": {family: "ripemd160", name: "RIPEMD-160"},
	"whirlpool": {family: "whirlpool", name: "Whirlpool"},
}

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
		info = struct {
			family string
			name   string
		}{family: normalizedAlgo, name: algoName}
	}

	qi := quantum.GetInfo(info.family)
	severity := hashSeverity(info.family)

	return &types.Finding{
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      info.name,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  severity,
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
		info = struct {
			family string
			name   string
		}{family: normalizedAlgo, name: algoName}
	}

	name := fmt.Sprintf("HMAC-%s", info.name)
	qi := quantum.GetInfo(info.family)

	return &types.Finding{
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      name,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  types.SeverityInfo,
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
		info = struct {
			family string
			name   string
		}{family: normalizedAlgo, name: algoName}
	}

	name := fmt.Sprintf("PBKDF2-%s", info.name)
	severity := types.SeverityInfo

	// Check iteration count (4th argument, index 3)
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

// passwordAlgoMap maps PHP PASSWORD_* constants to algorithm details.
var passwordAlgoMap = map[string]struct {
	family string
	name   string
}{
	"PASSWORD_BCRYPT":  {family: "bcrypt", name: "bcrypt"},
	"PASSWORD_ARGON2I": {family: "argon2", name: "Argon2i"},
	"PASSWORD_ARGON2ID": {family: "argon2", name: "Argon2id"},
	"PASSWORD_DEFAULT": {family: "bcrypt", name: "bcrypt (default)"},
}

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
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      "password_verify",
				Location:  scanner.NodeLocation(callNode, path, content),
				Severity:  types.SeverityInfo,
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
		ID:        nextFindingID(),
		AssetType: types.AssetAlgorithm,
		Name:      name,
		Location:  scanner.NodeLocation(callNode, path, content),
		Severity:  types.SeverityInfo,
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

// sodiumFuncMap maps sodium_* function names to crypto details.
var sodiumFuncMap = map[string]struct {
	family    string
	name      string
	primitive string
	funcs     []string
}{
	"sodium_crypto_secretbox":      {family: "xsalsa20", name: "XSalsa20-Poly1305 (secretbox)", primitive: "ae", funcs: []string{"encrypt"}},
	"sodium_crypto_secretbox_open": {family: "xsalsa20", name: "XSalsa20-Poly1305 (secretbox)", primitive: "ae", funcs: []string{"decrypt"}},
	"sodium_crypto_box":            {family: "x25519", name: "X25519-XSalsa20-Poly1305 (box)", primitive: "pke", funcs: []string{"encrypt"}},
	"sodium_crypto_box_open":       {family: "x25519", name: "X25519-XSalsa20-Poly1305 (box)", primitive: "pke", funcs: []string{"decrypt"}},
	"sodium_crypto_box_keypair":    {family: "x25519", name: "X25519 Key Pair", primitive: "key-agree", funcs: []string{"generate"}},
	"sodium_crypto_sign":           {family: "ed25519", name: "Ed25519 (sign)", primitive: "signature", funcs: []string{"sign"}},
	"sodium_crypto_sign_open":      {family: "ed25519", name: "Ed25519 (verify)", primitive: "signature", funcs: []string{"verify"}},
	"sodium_crypto_sign_keypair":   {family: "ed25519", name: "Ed25519 Key Pair", primitive: "signature", funcs: []string{"generate"}},
	"sodium_crypto_aead_chacha20poly1305_encrypt":       {family: "chacha20", name: "ChaCha20-Poly1305 (AEAD)", primitive: "ae", funcs: []string{"encrypt"}},
	"sodium_crypto_aead_chacha20poly1305_decrypt":       {family: "chacha20", name: "ChaCha20-Poly1305 (AEAD)", primitive: "ae", funcs: []string{"decrypt"}},
	"sodium_crypto_aead_chacha20poly1305_ietf_encrypt":  {family: "chacha20", name: "ChaCha20-Poly1305-IETF (AEAD)", primitive: "ae", funcs: []string{"encrypt"}},
	"sodium_crypto_aead_chacha20poly1305_ietf_decrypt":  {family: "chacha20", name: "ChaCha20-Poly1305-IETF (AEAD)", primitive: "ae", funcs: []string{"decrypt"}},
	"sodium_crypto_aead_xchacha20poly1305_ietf_encrypt": {family: "chacha20", name: "XChaCha20-Poly1305-IETF (AEAD)", primitive: "ae", funcs: []string{"encrypt"}},
	"sodium_crypto_aead_xchacha20poly1305_ietf_decrypt": {family: "chacha20", name: "XChaCha20-Poly1305-IETF (AEAD)", primitive: "ae", funcs: []string{"decrypt"}},
	"sodium_crypto_generichash":    {family: "blake2b", name: "BLAKE2b (generichash)", primitive: "hash", funcs: []string{"digest"}},
	"sodium_crypto_pwhash":         {family: "argon2", name: "Argon2id (pwhash)", primitive: "kdf", funcs: []string{"derive"}},
	"sodium_crypto_shorthash":      {family: "siphash", name: "SipHash-2-4 (shorthash)", primitive: "hash", funcs: []string{"digest"}},
}

func (s *PHPScanner) detectSodium(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	s.walkForFunctionCalls(root, content, func(fnName string, callNode *sitter.Node, _ *sitter.Node) {
		info, ok := sodiumFuncMap[fnName]
		if !ok {
			return
		}

		qi := quantum.GetInfo(info.family)

		findings = append(findings, types.Finding{
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      info.name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  types.SeverityInfo,
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

// mcryptFuncMap maps mcrypt_* function names to crypto details.
var mcryptFuncMap = map[string]struct {
	funcs []string
}{
	"mcrypt_encrypt":       {funcs: []string{"encrypt"}},
	"mcrypt_decrypt":       {funcs: []string{"decrypt"}},
	"mcrypt_cbc":           {funcs: []string{"encrypt", "decrypt"}},
	"mcrypt_ecb":           {funcs: []string{"encrypt", "decrypt"}},
	"mcrypt_cfb":           {funcs: []string{"encrypt", "decrypt"}},
	"mcrypt_ofb":           {funcs: []string{"encrypt", "decrypt"}},
	"mcrypt_generic":       {funcs: []string{"encrypt"}},
	"mdecrypt_generic":     {funcs: []string{"decrypt"}},
	"mcrypt_module_open":   {funcs: []string{"init"}},
}

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
			ID:        nextFindingID(),
			AssetType: types.AssetAlgorithm,
			Name:      name,
			Location:  scanner.NodeLocation(callNode, path, content),
			Severity:  types.SeverityHigh,
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
