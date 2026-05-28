// Package cpp detects cryptographic API usage in C and C++ source files.
//
// C/C++ cryptographic operations span multiple libraries: OpenSSL (EVP, RSA,
// AES, SHA, HMAC, PEM, SSL), libsodium (crypto_secretbox, crypto_box,
// crypto_sign, crypto_aead, crypto_pwhash), and mbedTLS (mbedtls_aes,
// mbedtls_rsa, mbedtls_sha256, mbedtls_ssl). The scanner uses tree-sitter's
// C and C++ grammars to parse source files and match function call patterns,
// with constant propagation for algorithm arguments passed via variables.
package cpp

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	cLang "github.com/smacker/go-tree-sitter/c"
	cppLang "github.com/smacker/go-tree-sitter/cpp"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// CppScanner detects cryptographic API usage in C/C++ source files.
type CppScanner struct {
	cLang   *sitter.Language
	cppLang *sitter.Language
}

// New creates a new CppScanner instance.
func New() *CppScanner {
	return &CppScanner{
		cLang:   cLang.GetLanguage(),
		cppLang: cppLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *CppScanner) Name() string {
	return "cpp"
}

// Extensions returns the file extensions this scanner handles.
func (s *CppScanner) Extensions() []string {
	return []string{".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}
}

// langForExt returns the correct tree-sitter language for a file extension.
func (s *CppScanner) langForExt(path string) *sitter.Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".c", ".h":
		return s.cLang
	default:
		return s.cppLang
	}
}

// ScanFile scans a single C/C++ file's content and returns cryptographic findings.
func (s *CppScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	lang := s.langForExt(path)
	root, err := scanner.ParseWithTreeSitter(content, lang)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Collect constant propagation data
	cp := NewConstPropagator()
	cp.CollectAssignments(root, content)

	var findings []types.Finding

	// Detect OpenSSL EVP usage
	findings = append(findings, s.detectOpenSSLEVP(root, path, content, cp)...)

	// Detect OpenSSL hash functions
	findings = append(findings, s.detectOpenSSLHash(root, path, content)...)

	// Detect OpenSSL RSA usage
	findings = append(findings, s.detectOpenSSLRSA(root, path, content, cp)...)

	// Detect OpenSSL AES usage
	findings = append(findings, s.detectOpenSSLAES(root, path, content)...)

	// Detect OpenSSL HMAC usage
	findings = append(findings, s.detectOpenSSLHMAC(root, path, content)...)

	// Detect OpenSSL KDF usage (PBKDF2)
	findings = append(findings, s.detectOpenSSLKDF(root, path, content)...)

	// Detect OpenSSL PEM usage
	findings = append(findings, s.detectOpenSSLPEM(root, path, content)...)

	// Detect OpenSSL SSL/TLS usage
	findings = append(findings, s.detectOpenSSLSSL(root, path, content, cp)...)

	// Detect libsodium usage
	findings = append(findings, s.detectLibsodium(root, path, content)...)

	// Detect mbedTLS usage
	findings = append(findings, s.detectMbedTLS(root, path, content)...)

	return scanner.AnnotateFindings(findings), nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// OpenSSL EVP detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLEVP(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// EVP_EncryptInit / EVP_EncryptInit_ex — generic symmetric encryption
	for _, funcName := range []string{"EVP_EncryptInit", "EVP_EncryptInit_ex"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "EVP-Encrypt",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "aes",
					CryptoFunctions: []string{"encrypt"},
				},
				Description: fmt.Sprintf("Symmetric encryption via %s()", funcName),
				RuleID:      "cbom-cpp-evp-encryptinit",
				Pass:        1,
			})
		}
	}

	// EVP_DecryptInit / EVP_DecryptInit_ex
	for _, funcName := range []string{"EVP_DecryptInit", "EVP_DecryptInit_ex"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "EVP-Decrypt",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "aes",
					CryptoFunctions: []string{"decrypt"},
				},
				Description: fmt.Sprintf("Symmetric decryption via %s()", funcName),
				RuleID:      "cbom-cpp-evp-decryptinit",
				Pass:        1,
			})
		}
	}

	// EVP_DigestInit / EVP_DigestInit_ex — generic hashing
	for _, funcName := range []string{"EVP_DigestInit", "EVP_DigestInit_ex"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "EVP-Digest",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "hash",
					AlgorithmFamily: "sha-256",
					CryptoFunctions: []string{"digest"},
				},
				Description: fmt.Sprintf("Hash digest via %s()", funcName),
				RuleID:      "cbom-cpp-evp-digestinit",
				Pass:        1,
			})
		}
	}

	// EVP_DigestSignInit — signing
	for _, callNode := range findFunctionCalls(root, content, "EVP_DigestSignInit") {
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "EVP-DigestSign",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "signature",
				AlgorithmFamily: "rsa",
				CryptoFunctions: []string{"sign"},
			},
			Description: "Digital signature via EVP_DigestSignInit()",
			RuleID:      "cbom-cpp-evp-digestsigninit",
			Pass:        1,
		})
	}

	// EVP_DigestVerifyInit — verification
	for _, callNode := range findFunctionCalls(root, content, "EVP_DigestVerifyInit") {
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "EVP-DigestVerify",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "signature",
				AlgorithmFamily: "rsa",
				CryptoFunctions: []string{"verify"},
			},
			Description: "Signature verification via EVP_DigestVerifyInit()",
			RuleID:      "cbom-cpp-evp-digestverifyinit",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL hash detection (SHA256, MD5, SHA1)
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLHash(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// SHA256
	for _, funcName := range []string{"SHA256", "SHA256_Init", "SHA256_Update", "SHA256_Final"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("sha-256")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "SHA-256",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  "sha-256",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("SHA-256 hash via %s()", funcName),
				RuleID:      "cbom-cpp-sha256",
				Pass:        1,
			})
		}
	}

	// SHA512
	for _, funcName := range []string{"SHA512", "SHA512_Init", "SHA512_Update", "SHA512_Final"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("sha-512")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "SHA-512",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  "sha-512",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("SHA-512 hash via %s()", funcName),
				RuleID:      "cbom-cpp-sha512",
				Pass:        1,
			})
		}
	}

	// MD5 (broken, HIGH severity)
	for _, funcName := range []string{"MD5", "MD5_Init", "MD5_Update", "MD5_Final"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("md5")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "MD5",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  "md5",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("MD5 hash via %s() — broken, do not use", funcName),
				RuleID:      "cbom-cpp-md5",
				Pass:        1,
			})
		}
	}

	// SHA1 (broken, HIGH severity)
	for _, funcName := range []string{"SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("sha1")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "SHA-1",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  "sha1",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("SHA-1 hash via %s() — broken, do not use", funcName),
				RuleID:      "cbom-cpp-sha1",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL RSA detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLRSA(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// RSA_generate_key / RSA_generate_key_ex
	for _, funcName := range []string{"RSA_generate_key", "RSA_generate_key_ex"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("rsa")
			keySize := extractNthIntArg(callNode, content, cp, 0)
			name := "RSA"
			if keySize > 0 {
				name = fmt.Sprintf("RSA-%d", keySize)
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(callNode, path, content),
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
				Description: fmt.Sprintf("RSA key generation via %s()", funcName),
				RuleID:      "cbom-cpp-rsa-generate-key",
				Pass:        1,
			})
		}
	}

	// EVP_PKEY_CTX_new_id — generic key context (RSA, EC)
	for _, callNode := range findFunctionCalls(root, content, "EVP_PKEY_CTX_new_id") {
		qi := quantum.GetInfo("rsa")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "EVP-PKEY",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceMedium,
			Properties: types.CryptoProperties{
				Primitive:        "pke",
				AlgorithmFamily:  "rsa",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"generate"},
			},
			Description: "Public key context via EVP_PKEY_CTX_new_id()",
			RuleID:      "cbom-cpp-evp-pkey-ctx",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL AES detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLAES(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// AES_set_encrypt_key / AES_set_decrypt_key
	for _, funcName := range []string{"AES_set_encrypt_key", "AES_set_decrypt_key"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("aes")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "AES",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "block-cipher",
					AlgorithmFamily:  "aes",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("AES block cipher via %s()", funcName),
				RuleID:      "cbom-cpp-aes-set-key",
				Pass:        1,
			})
		}
	}

	// AES_encrypt / AES_decrypt
	for _, funcName := range []string{"AES_encrypt", "AES_decrypt"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("aes")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "AES-ECB",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "block-cipher",
					AlgorithmFamily:  "aes",
					Mode:             "ecb",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("AES ECB mode via %s() — ECB mode is insecure", funcName),
				RuleID:      "cbom-cpp-aes-ecb",
				Pass:        1,
			})
		}
	}

	// DES_set_key / DES_ecb_encrypt (broken, HIGH severity)
	for _, funcName := range []string{"DES_set_key", "DES_ecb_encrypt", "DES_ncbc_encrypt"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("des")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "DES",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "block-cipher",
					AlgorithmFamily:  "des",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("DES block cipher via %s() — broken, do not use", funcName),
				RuleID:      "cbom-cpp-des",
				Pass:        1,
			})
		}
	}

	// RC4 (broken, HIGH severity)
	for _, funcName := range []string{"RC4", "RC4_set_key"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("rc4")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "RC4",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "stream-cipher",
					AlgorithmFamily:  "rc4",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("RC4 stream cipher via %s() — broken, do not use", funcName),
				RuleID:      "cbom-cpp-rc4",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL HMAC detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLHMAC(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	for _, funcName := range []string{"HMAC", "HMAC_Init", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
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
				Description: fmt.Sprintf("HMAC via %s()", funcName),
				RuleID:      "cbom-cpp-hmac",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL KDF detection (PBKDF2)
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLKDF(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// PKCS5_PBKDF2_HMAC / PKCS5_PBKDF2_HMAC_SHA1 — password-based key derivation.
	// Match the specific OpenSSL function names only to avoid false positives.
	for _, funcName := range []string{"PKCS5_PBKDF2_HMAC", "PKCS5_PBKDF2_HMAC_SHA1"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("pbkdf2")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "PBKDF2",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "kdf",
					AlgorithmFamily:  "pbkdf2",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"keyderive"},
				},
				Description: fmt.Sprintf("PBKDF2 key derivation via %s()", funcName),
				RuleID:      "cbom-cpp-pbkdf2",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL PEM detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectOpenSSLPEM(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	for _, funcName := range []string{"PEM_read_PrivateKey", "PEM_read_bio_PrivateKey", "PEM_write_PrivateKey", "PEM_write_bio_PrivateKey"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetRelatedCryptoMaterial,
				Name:       "PEM-PrivateKey",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					MaterialType: "private-key",
				},
				Description: fmt.Sprintf("PEM private key I/O via %s()", funcName),
				RuleID:      "cbom-cpp-pem-privatekey",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// OpenSSL SSL/TLS detection
// ---------------------------------------------------------------------------

// tlsMethodMap maps OpenSSL SSL method functions to TLS version info.
var tlsMethodMap = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"TLS_method":       {name: "TLS", version: "", severity: types.SeverityInfo},
	"TLS_client_method": {name: "TLS", version: "", severity: types.SeverityInfo},
	"TLS_server_method": {name: "TLS", version: "", severity: types.SeverityInfo},
	"TLSv1_method":     {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"TLSv1_client_method": {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"TLSv1_server_method": {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"TLSv1_1_method":   {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"TLSv1_1_client_method": {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"TLSv1_1_server_method": {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"TLSv1_2_method":   {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"TLSv1_2_client_method": {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"TLSv1_2_server_method": {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"SSLv23_method":    {name: "SSL 2.0/3.0", version: "2.0", severity: types.SeverityHigh},
	"SSLv3_method":     {name: "SSL 3.0", version: "3.0", severity: types.SeverityHigh},
}

// tlsVersionConstants maps OpenSSL TLS version macro values for SSL_CTX_set_min_proto_version.
var tlsVersionConstants = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"TLS1_VERSION":   {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"TLS1_1_VERSION": {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"TLS1_2_VERSION": {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"TLS1_3_VERSION": {name: "TLS 1.3", version: "1.3", severity: types.SeverityInfo},
	"SSL3_VERSION":   {name: "SSL 3.0", version: "3.0", severity: types.SeverityHigh},
}

func (s *CppScanner) detectOpenSSLSSL(root *sitter.Node, path string, content []byte, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// SSL_CTX_new(method)
	for _, callNode := range findFunctionCalls(root, content, "SSL_CTX_new") {
		// Try to resolve the method argument
		argStr := extractNthRawArg(callNode, content, 0)
		argStr = strings.TrimSpace(argStr)
		// Strip trailing ()
		argStr = strings.TrimSuffix(argStr, "()")

		if info, ok := tlsMethodMap[argStr]; ok {
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
				Description: fmt.Sprintf("TLS context via SSL_CTX_new(%s())", argStr),
				RuleID:      "cbom-cpp-ssl-ctx-new",
				Pass:        1,
			})
		} else {
			// Generic SSL_CTX_new detection
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetProtocol,
				Name:       "TLS",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					ProtocolType: "tls",
				},
				Description: "TLS context via SSL_CTX_new()",
				RuleID:      "cbom-cpp-ssl-ctx-new",
				Pass:        1,
			})
		}
	}

	// SSL_CTX_set_min_proto_version(ctx, version)
	for _, callNode := range findFunctionCalls(root, content, "SSL_CTX_set_min_proto_version") {
		argStr := extractNthRawArg(callNode, content, 1)
		argStr = strings.TrimSpace(argStr)

		if info, ok := tlsVersionConstants[argStr]; ok {
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
				Description: fmt.Sprintf("TLS min version set to %s via SSL_CTX_set_min_proto_version()", info.version),
				RuleID:      "cbom-cpp-ssl-min-proto",
				Pass:        1,
			})
		} else {
			// If we can resolve via const prop
			if resolved, ok := cp.Resolve(argStr); ok {
				if info, ok := tlsVersionConstants[resolved]; ok {
					findings = append(findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetProtocol,
						Name:       info.name,
						Location:   scanner.NodeLocation(callNode, path, content),
						Severity:   info.severity,
						Confidence: types.ConfidenceMedium,
						Properties: types.CryptoProperties{
							ProtocolType:    "tls",
							ProtocolVersion: info.version,
						},
						Description: fmt.Sprintf("TLS min version set to %s via SSL_CTX_set_min_proto_version()", info.version),
						RuleID:      "cbom-cpp-ssl-min-proto",
						Pass:        1,
					})
				}
			}
		}
	}

	// SSL_CTX_set_max_proto_version(ctx, version)
	for _, callNode := range findFunctionCalls(root, content, "SSL_CTX_set_max_proto_version") {
		argStr := extractNthRawArg(callNode, content, 1)
		argStr = strings.TrimSpace(argStr)

		if info, ok := tlsVersionConstants[argStr]; ok {
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
				Description: fmt.Sprintf("TLS max version set to %s via SSL_CTX_set_max_proto_version()", info.version),
				RuleID:      "cbom-cpp-ssl-max-proto",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// libsodium detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectLibsodium(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// crypto_secretbox / crypto_secretbox_open
	for _, funcName := range []string{"crypto_secretbox", "crypto_secretbox_easy", "crypto_secretbox_open_easy"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("chacha20")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "XSalsa20-Poly1305",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "ae",
					AlgorithmFamily:  "chacha20",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("Authenticated encryption via %s()", funcName),
				RuleID:      "cbom-cpp-sodium-secretbox",
				Pass:        1,
			})
		}
	}

	// crypto_box / crypto_box_open
	for _, funcName := range []string{"crypto_box", "crypto_box_easy", "crypto_box_open_easy", "crypto_box_keypair"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("x25519")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "Curve25519-XSalsa20-Poly1305",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "ae",
					AlgorithmFamily:  "x25519",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("Public-key authenticated encryption via %s()", funcName),
				RuleID:      "cbom-cpp-sodium-box",
				Pass:        1,
			})
		}
	}

	// crypto_sign / crypto_sign_open / crypto_sign_keypair
	for _, funcName := range []string{"crypto_sign", "crypto_sign_detached", "crypto_sign_open", "crypto_sign_verify_detached", "crypto_sign_keypair", "crypto_sign_ed25519_keypair"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("ed25519")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "Ed25519",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "signature",
					AlgorithmFamily:  "ed25519",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"sign"},
				},
				Description: fmt.Sprintf("Ed25519 signature via %s()", funcName),
				RuleID:      "cbom-cpp-sodium-sign",
				Pass:        1,
			})
		}
	}

	// crypto_aead_* (AEAD constructions)
	aeadFuncs := []string{
		"crypto_aead_xchacha20poly1305_ietf_encrypt",
		"crypto_aead_xchacha20poly1305_ietf_decrypt",
		"crypto_aead_chacha20poly1305_ietf_encrypt",
		"crypto_aead_chacha20poly1305_ietf_decrypt",
		"crypto_aead_chacha20poly1305_encrypt",
		"crypto_aead_chacha20poly1305_decrypt",
		"crypto_aead_aes256gcm_encrypt",
		"crypto_aead_aes256gcm_decrypt",
	}
	for _, funcName := range aeadFuncs {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("chacha20")
			name := "ChaCha20-Poly1305"
			family := "chacha20"
			if strings.Contains(funcName, "aes256gcm") {
				qi = quantum.GetInfo("aes-256")
				name = "AES-256-GCM"
				family = "aes"
			}
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "ae",
					AlgorithmFamily:  family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("AEAD encryption via %s()", funcName),
				RuleID:      "cbom-cpp-sodium-aead",
				Pass:        1,
			})
		}
	}

	// crypto_pwhash (password hashing)
	for _, funcName := range []string{"crypto_pwhash", "crypto_pwhash_str", "crypto_pwhash_str_verify"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "Argon2",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "kdf",
					AlgorithmFamily: "argon2",
					CryptoFunctions: []string{"passwordhash"},
				},
				Description: fmt.Sprintf("Password hashing via %s()", funcName),
				RuleID:      "cbom-cpp-sodium-pwhash",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// mbedTLS detection
// ---------------------------------------------------------------------------

func (s *CppScanner) detectMbedTLS(root *sitter.Node, path string, content []byte) []types.Finding {
	var findings []types.Finding

	// mbedtls_aes_* — AES
	for _, funcName := range []string{"mbedtls_aes_init", "mbedtls_aes_setkey_enc", "mbedtls_aes_setkey_dec", "mbedtls_aes_crypt_ecb", "mbedtls_aes_crypt_cbc"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("aes")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "AES",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "block-cipher",
					AlgorithmFamily:  "aes",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("AES via mbedTLS %s()", funcName),
				RuleID:      "cbom-cpp-mbedtls-aes",
				Pass:        1,
			})
		}
	}

	// mbedtls_rsa_* — RSA
	for _, funcName := range []string{"mbedtls_rsa_init", "mbedtls_rsa_gen_key", "mbedtls_rsa_pkcs1_encrypt", "mbedtls_rsa_pkcs1_decrypt", "mbedtls_rsa_pkcs1_sign", "mbedtls_rsa_pkcs1_verify"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("rsa")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "RSA",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "pke",
					AlgorithmFamily:  "rsa",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("RSA via mbedTLS %s()", funcName),
				RuleID:      "cbom-cpp-mbedtls-rsa",
				Pass:        1,
			})
		}
	}

	// mbedtls_sha256_* — SHA-256
	for _, funcName := range []string{"mbedtls_sha256_init", "mbedtls_sha256_starts", "mbedtls_sha256_update", "mbedtls_sha256_finish", "mbedtls_sha256"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			qi := quantum.GetInfo("sha-256")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "SHA-256",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "hash",
					AlgorithmFamily:  "sha-256",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"digest"},
				},
				Description: fmt.Sprintf("SHA-256 hash via mbedTLS %s()", funcName),
				RuleID:      "cbom-cpp-mbedtls-sha256",
				Pass:        1,
			})
		}
	}

	// mbedtls_ssl_* — TLS
	for _, funcName := range []string{"mbedtls_ssl_init", "mbedtls_ssl_setup", "mbedtls_ssl_config_defaults"} {
		for _, callNode := range findFunctionCalls(root, content, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetProtocol,
				Name:       "TLS",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType: "tls",
				},
				Description: fmt.Sprintf("TLS via mbedTLS %s()", funcName),
				RuleID:      "cbom-cpp-mbedtls-ssl",
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Tree-sitter helpers
// ---------------------------------------------------------------------------

// findFunctionCalls finds call_expression nodes where the function name matches.
// Handles both plain function calls (e.g., SHA256()) and namespace-qualified
// calls in C++ (e.g., OpenSSL::SHA256()).
func findFunctionCalls(root *sitter.Node, content []byte, funcName string) []*sitter.Node {
	var nodes []*sitter.Node
	walkForFunctionCalls(root, content, funcName, &nodes)
	return nodes
}

func walkForFunctionCalls(node *sitter.Node, content []byte, funcName string, nodes *[]*sitter.Node) {
	if node == nil {
		return
	}

	if node.Type() == "call_expression" {
		fnNode := node.ChildByFieldName("function")
		if fnNode != nil {
			fnText := fnNode.Content(content)
			// Match exact function name or qualified name ending in ::funcName
			if fnText == funcName || strings.HasSuffix(fnText, "::"+funcName) {
				*nodes = append(*nodes, node)
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			walkForFunctionCalls(child, content, funcName, nodes)
		}
	}
}

// findChildByType finds the first direct child of a given node type.
func findChildByType(node *sitter.Node, nodeType string) *sitter.Node {
	if node == nil {
		return nil
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() == nodeType {
			return child
		}
	}
	return nil
}

// extractNthRawArg extracts the raw text of the nth argument (0-indexed) from a
// call_expression node.
func extractNthRawArg(callNode *sitter.Node, content []byte, n int) string {
	argsNode := findChildByType(callNode, "argument_list")
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
		if posIdx == n {
			return child.Content(content)
		}
		posIdx++
	}
	return ""
}

// extractNthIntArg extracts the nth argument as an integer, using constant propagation.
func extractNthIntArg(callNode *sitter.Node, content []byte, cp *ConstPropagator, n int) int {
	raw := extractNthRawArg(callNode, content, n)
	if raw == "" {
		return 0
	}

	// Try direct integer parsing
	raw = strings.TrimSpace(raw)
	if val, err := strconv.Atoi(raw); err == nil {
		return val
	}

	// Try constant propagation
	if resolved, ok := cp.Resolve(raw); ok {
		if val, err := strconv.Atoi(resolved); err == nil {
			return val
		}
	}

	return 0
}
