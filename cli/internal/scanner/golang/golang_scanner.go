package golang

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
	goLang "github.com/smacker/go-tree-sitter/golang"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kdf"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// GoScanner detects cryptographic API usage in Go source files.
type GoScanner struct {
	lang *sitter.Language
}

// New creates a new GoScanner instance.
func New() *GoScanner {
	return &GoScanner{
		lang: goLang.GetLanguage(),
	}
}

// Name returns the scanner's language name.
func (s *GoScanner) Name() string {
	return "go"
}

// Extensions returns the file extensions this scanner handles.
func (s *GoScanner) Extensions() []string {
	return []string{".go"}
}

// ScanFile scans a single Go file's content and returns cryptographic findings.
func (s *GoScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	root, err := scanner.ParseWithTreeSitter(content, s.lang)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Collect import paths
	imports := s.collectImports(root, content)

	// Collect constant propagation data
	cp := NewConstPropagator()
	cp.CollectAssignments(root, content)

	var findings []types.Finding

	// Detect crypto/aes usage
	findings = append(findings, s.detectCryptoAES(root, path, content, imports)...)

	// Detect crypto/cipher usage
	findings = append(findings, s.detectCryptoCipher(root, path, content, imports)...)

	// Detect crypto/des usage
	findings = append(findings, s.detectCryptoDES(root, path, content, imports)...)

	// Detect crypto/md5 usage
	findings = append(findings, s.detectCryptoMD5(root, path, content, imports)...)

	// Detect crypto/rc4 usage
	findings = append(findings, s.detectCryptoRC4(root, path, content, imports)...)

	// Detect crypto/sha1 usage
	findings = append(findings, s.detectCryptoSHA1(root, path, content, imports)...)

	// Detect crypto/sha256 usage
	findings = append(findings, s.detectCryptoSHA256(root, path, content, imports)...)

	// Detect crypto/sha512 usage
	findings = append(findings, s.detectCryptoSHA512(root, path, content, imports)...)

	// Detect crypto/hmac usage
	findings = append(findings, s.detectCryptoHMAC(root, path, content, imports)...)

	// Detect crypto/rsa usage
	findings = append(findings, s.detectCryptoRSA(root, path, content, imports, cp)...)

	// Detect crypto/dsa usage
	findings = append(findings, s.detectCryptoDSA(root, path, content, imports)...)

	// Detect crypto/ecdsa usage
	findings = append(findings, s.detectCryptoECDSA(root, path, content, imports)...)

	// Detect crypto/ecdh usage
	findings = append(findings, s.detectCryptoECDH(root, path, content, imports)...)

	// Detect crypto/ed25519 usage
	findings = append(findings, s.detectCryptoEd25519(root, path, content, imports)...)

	// Detect crypto/tls usage
	findings = append(findings, s.detectCryptoTLS(root, path, content, imports)...)

	// Detect crypto/x509 usage
	findings = append(findings, s.detectCryptoX509(root, path, content, imports)...)

	// Detect golang.org/x/crypto packages
	findings = append(findings, s.detectXCrypto(root, path, content, imports, cp)...)

	// Detect Schnorr (BIP-340) signatures (btcec/decred secp256k1)
	findings = append(findings, s.detectSchnorr(root, path, content, imports)...)

	// Detect BLS / BLS12-381 signatures (kilic / herumi / prysm)
	findings = append(findings, s.detectBLS(root, path, content, imports)...)

	// Detect tjfoc/gmsm SM2 usage
	findings = append(findings, s.detectSM2(root, path, content, imports)...)

	return scanner.AnnotateFindings(findings), nil
}

// nextFindingID generates a unique finding ID.
func nextFindingID() string {
	id := findingCounter.Add(1)
	return fmt.Sprintf("FIND-%d", id)
}

// ---------------------------------------------------------------------------
// Import collection
// ---------------------------------------------------------------------------

// importInfo holds information about an imported package.
type importInfo struct {
	path  string // full import path, e.g. "crypto/aes"
	alias string // local alias, e.g. "aes" or a custom alias
}

// collectImports walks the AST and collects all import declarations.
// Returns a map of local alias -> import path.
func (s *GoScanner) collectImports(root *sitter.Node, content []byte) map[string]string {
	imports := make(map[string]string)
	s.walkForImports(root, content, imports)
	return imports
}

func (s *GoScanner) walkForImports(node *sitter.Node, content []byte, imports map[string]string) {
	if node == nil {
		return
	}

	if node.Type() == "import_spec" {
		s.processImportSpec(node, content, imports)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			s.walkForImports(child, content, imports)
		}
	}
}

func (s *GoScanner) processImportSpec(node *sitter.Node, content []byte, imports map[string]string) {
	var alias string
	var importPath string

	nameNode := node.ChildByFieldName("name")
	pathNode := node.ChildByFieldName("path")

	if pathNode == nil {
		return
	}

	importPath = unquoteGoString(pathNode.Content(content))

	if nameNode != nil {
		alias = nameNode.Content(content)
	} else {
		// Default alias is the last path component
		parts := strings.Split(importPath, "/")
		alias = parts[len(parts)-1]
	}

	imports[alias] = importPath
}

// hasImport checks if a given import path is present.
func hasImport(imports map[string]string, path string) bool {
	for _, p := range imports {
		if p == path {
			return true
		}
	}
	return false
}

// aliasFor returns the local alias for a given import path.
func aliasFor(imports map[string]string, path string) string {
	for alias, p := range imports {
		if p == path {
			return alias
		}
	}
	return ""
}

// aliasForAny returns the local alias for the first import path whose full
// path equals, or whose final path segment equals, any of the supplied
// candidate package paths/names. Used for third-party libraries that ship the
// same package under several module paths (e.g. the "schnorr" sub-package of
// both btcsuite/btcd and decred/dcrd). Matching the final segment keeps the
// candidate list short while still being import-anchored (zero bare-word FP).
func aliasForAny(imports map[string]string, candidates ...string) string {
	for alias, p := range imports {
		last := p
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			last = p[idx+1:]
		}
		for _, c := range candidates {
			if p == c || last == c {
				return alias
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// crypto/aes detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoAES(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/aes")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// Match aes.NewCipher(key)
	callNodes := s.findSelectorCalls(root, content, alias, "NewCipher")
	for _, callNode := range callNodes {
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
			Description: fmt.Sprintf("AES block cipher via %s.NewCipher()", alias),
			RuleID:      "cbom-go-aes-newcipher",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/cipher detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoCipher(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/cipher")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// cipher.NewGCM(block)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewGCM") {
		qi := quantum.GetInfo("aes")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "AES-GCM",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "ae",
				AlgorithmFamily:  "aes",
				Mode:             "gcm",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt"},
			},
			Description: fmt.Sprintf("AES-GCM authenticated encryption via %s.NewGCM()", alias),
			RuleID:      "cbom-go-cipher-gcm",
			Pass:        1,
		})
	}

	// cipher.NewCBCEncrypter / cipher.NewCBCDecrypter
	for _, funcName := range []string{"NewCBCEncrypter", "NewCBCDecrypter"} {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("aes")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "AES-CBC",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "block-cipher",
					AlgorithmFamily:  "aes",
					Mode:             "cbc",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("AES-CBC via %s.%s()", alias, funcName),
				RuleID:      "cbom-go-cipher-cbc",
				Pass:        1,
			})
		}
	}

	// cipher.NewCTR
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewCTR") {
		qi := quantum.GetInfo("aes")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "AES-CTR",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "block-cipher",
				AlgorithmFamily:  "aes",
				Mode:             "ctr",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt"},
			},
			Description: fmt.Sprintf("AES-CTR via %s.NewCTR()", alias),
			RuleID:      "cbom-go-cipher-ctr",
			Pass:        1,
		})
	}

	// cipher.NewOFB
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewOFB") {
		qi := quantum.GetInfo("aes")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "AES-OFB",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "block-cipher",
				AlgorithmFamily:  "aes",
				Mode:             "ofb",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt"},
			},
			Description: fmt.Sprintf("AES-OFB via %s.NewOFB()", alias),
			RuleID:      "cbom-go-cipher-ofb",
			Pass:        1,
		})
	}

	// cipher.NewCFBEncrypter
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewCFBEncrypter") {
		qi := quantum.GetInfo("aes")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "AES-CFB",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "block-cipher",
				AlgorithmFamily:  "aes",
				Mode:             "cfb",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt"},
			},
			Description: fmt.Sprintf("AES-CFB via %s.NewCFBEncrypter()", alias),
			RuleID:      "cbom-go-cipher-cfb",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/des detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoDES(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/des")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// des.NewCipher(key) -> DES (broken)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewCipher") {
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
			Description: fmt.Sprintf("DES block cipher via %s.NewCipher() — broken, do not use", alias),
			RuleID:      "cbom-go-des-newcipher",
			Pass:        1,
		})
	}

	// des.NewTripleDESCipher(key) -> 3DES (broken)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewTripleDESCipher") {
		qi := quantum.GetInfo("3des")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "3DES",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityHigh,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "block-cipher",
				AlgorithmFamily:  "3des",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"encrypt"},
			},
			Description: fmt.Sprintf("3DES block cipher via %s.NewTripleDESCipher() — deprecated", alias),
			RuleID:      "cbom-go-des-tripledes",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/md5 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoMD5(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/md5")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// md5.New()
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New") {
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
			Description: fmt.Sprintf("MD5 hash via %s.New() — broken, do not use", alias),
			RuleID:      "cbom-go-md5-new",
			Pass:        1,
		})
	}

	// md5.Sum(data)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Sum") {
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
			Description: fmt.Sprintf("MD5 hash via %s.Sum() — broken, do not use", alias),
			RuleID:      "cbom-go-md5-sum",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/rc4 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoRC4(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/rc4")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// rc4.NewCipher(key)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "NewCipher") {
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
			Description: fmt.Sprintf("RC4 stream cipher via %s.NewCipher() — broken, do not use", alias),
			RuleID:      "cbom-go-rc4-newcipher",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/sha1 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoSHA1(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/sha1")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// sha1.New()
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New") {
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
			Description: fmt.Sprintf("SHA-1 hash via %s.New() — broken, do not use", alias),
			RuleID:      "cbom-go-sha1-new",
			Pass:        1,
		})
	}

	// sha1.Sum(data)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Sum") {
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
			Description: fmt.Sprintf("SHA-1 hash via %s.Sum() — broken, do not use", alias),
			RuleID:      "cbom-go-sha1-sum",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/sha256 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoSHA256(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/sha256")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// sha256.New() -> SHA-256
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New") {
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
			Description: fmt.Sprintf("SHA-256 hash via %s.New()", alias),
			RuleID:      "cbom-go-sha256-new",
			Pass:        1,
		})
	}

	// sha256.Sum256(data) -> SHA-256
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Sum256") {
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
			Description: fmt.Sprintf("SHA-256 hash via %s.Sum256()", alias),
			RuleID:      "cbom-go-sha256-sum256",
			Pass:        1,
		})
	}

	// sha256.New224() -> SHA-224
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New224") {
		qi := quantum.GetInfo("sha-256")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "SHA-224",
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
			Description: fmt.Sprintf("SHA-224 hash via %s.New224()", alias),
			RuleID:      "cbom-go-sha256-new224",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/sha512 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoSHA512(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/sha512")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// sha512.New() -> SHA-512
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New") {
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
			Description: fmt.Sprintf("SHA-512 hash via %s.New()", alias),
			RuleID:      "cbom-go-sha512-new",
			Pass:        1,
		})
	}

	// sha512.Sum512(data) -> SHA-512
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Sum512") {
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
			Description: fmt.Sprintf("SHA-512 hash via %s.Sum512()", alias),
			RuleID:      "cbom-go-sha512-sum512",
			Pass:        1,
		})
	}

	// sha512.New384() -> SHA-384
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New384") {
		qi := quantum.GetInfo("sha-384")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "SHA-384",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "hash",
				AlgorithmFamily:  "sha-384",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"digest"},
			},
			Description: fmt.Sprintf("SHA-384 hash via %s.New384()", alias),
			RuleID:      "cbom-go-sha512-new384",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/hmac detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoHMAC(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/hmac")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// hmac.New(hashFunc, key)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New") {
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
			Description: fmt.Sprintf("HMAC via %s.New()", alias),
			RuleID:      "cbom-go-hmac-new",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/rsa detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoRSA(root *sitter.Node, path string, content []byte, imports map[string]string, cp *ConstPropagator) []types.Finding {
	alias := aliasFor(imports, "crypto/rsa")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// rsa.GenerateKey(rand, bits)
	callNodes := s.findSelectorCalls(root, content, alias, "GenerateKey")
	for _, callNode := range callNodes {
		qi := quantum.GetInfo("rsa")
		keySize := s.extractRSAKeySize(callNode, content, cp)
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
			Description: fmt.Sprintf("RSA key generation via %s.GenerateKey()", alias),
			RuleID:      "cbom-go-rsa-generatekey",
			Pass:        1,
		})
	}

	// rsa.EncryptPKCS1v15, rsa.EncryptOAEP, rsa.SignPKCS1v15, rsa.SignPSS
	for _, funcName := range []string{"EncryptPKCS1v15", "EncryptOAEP", "DecryptPKCS1v15", "DecryptOAEP"} {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("rsa")
			// Flag PKCS1v15 as MEDIUM severity (padding oracle vulnerability)
			severity := types.SeverityInfo
			padding := ""
			if strings.Contains(funcName, "PKCS1v15") {
				severity = types.SeverityMedium
				padding = "pkcs1v15"
			}
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "RSA",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   severity,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "pke",
					AlgorithmFamily:  "rsa",
					Padding:          padding,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"encrypt"},
				},
				Description: fmt.Sprintf("RSA operation via %s.%s()", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-rsa-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	for _, funcName := range []string{"SignPKCS1v15", "SignPSS"} {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("rsa")
			// Flag PKCS1v15 as MEDIUM severity (padding oracle vulnerability)
			severity := types.SeverityInfo
			padding := ""
			if strings.Contains(funcName, "PKCS1v15") {
				severity = types.SeverityMedium
				padding = "pkcs1v15"
			}
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "RSA",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   severity,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "signature",
					AlgorithmFamily:  "rsa",
					Padding:          padding,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"sign"},
				},
				Description: fmt.Sprintf("RSA signature via %s.%s()", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-rsa-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// extractRSAKeySize tries to extract the key size (2nd argument) from an rsa.GenerateKey call.
func (s *GoScanner) extractRSAKeySize(callNode *sitter.Node, content []byte, cp *ConstPropagator) int {
	// Find the argument_list child
	argsNode := s.findChildByType(callNode, "argument_list")
	if argsNode == nil {
		return 0
	}

	val, _ := resolveNthArg(argsNode, 1, content, cp)
	if val == "" {
		return 0
	}
	size, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return size
}

// ---------------------------------------------------------------------------
// crypto/dsa detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoDSA(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/dsa")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	for _, funcName := range []string{"GenerateParameters", "GenerateKey"} {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("dsa")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "DSA",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "signature",
					AlgorithmFamily:  "dsa",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"generate"},
				},
				Description: fmt.Sprintf("DSA via %s.%s() — quantum-vulnerable", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-dsa-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/ecdsa detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoECDSA(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/ecdsa")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// ecdsa.GenerateKey(curve, rand)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "GenerateKey") {
		qi := quantum.GetInfo("ecdsa")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "ECDSA",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "signature",
				AlgorithmFamily:  "ecdsa",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"generate"},
			},
			Description: fmt.Sprintf("ECDSA key generation via %s.GenerateKey() — quantum-vulnerable", alias),
			RuleID:      "cbom-go-ecdsa-generatekey",
			Pass:        1,
		})
	}

	// ecdsa.Sign
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Sign") {
		qi := quantum.GetInfo("ecdsa")
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "ECDSA",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:        "signature",
				AlgorithmFamily:  "ecdsa",
				QuantumStatus:    qi.Status,
				NistQuantumLevel: qi.NistLevel,
				CryptoFunctions:  []string{"sign"},
			},
			Description: fmt.Sprintf("ECDSA signing via %s.Sign()", alias),
			RuleID:      "cbom-go-ecdsa-sign",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/ecdh detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoECDH(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/ecdh")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// ecdh.P256(), ecdh.P384(), ecdh.P521(), ecdh.X25519()
	curveNames := map[string]string{
		"P256":   "ECDH-P256",
		"P384":   "ECDH-P384",
		"P521":   "ECDH-P521",
		"X25519": "ECDH-X25519",
	}

	for funcName, curveName := range curveNames {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("ecdh")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       curveName,
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        "key-agree",
					AlgorithmFamily:  "ecdh",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{"keyagree"},
				},
				Description: fmt.Sprintf("ECDH curve %s via %s.%s() — quantum-vulnerable", curveName, alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-ecdh-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/ed25519 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoEd25519(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/ed25519")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// ed25519.GenerateKey(rand)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "GenerateKey") {
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
				CryptoFunctions:  []string{"generate"},
			},
			Description: fmt.Sprintf("Ed25519 key generation via %s.GenerateKey() — quantum-vulnerable", alias),
			RuleID:      "cbom-go-ed25519-generatekey",
			Pass:        1,
		})
	}

	// ed25519.Sign
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Sign") {
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
			Description: fmt.Sprintf("Ed25519 signing via %s.Sign()", alias),
			RuleID:      "cbom-go-ed25519-sign",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// crypto/tls detection
// ---------------------------------------------------------------------------

// tlsVersionConstants maps Go TLS version constant names to their info.
var tlsVersionConstants = map[string]struct {
	name     string
	version  string
	severity types.Severity
}{
	"VersionTLS10": {name: "TLS 1.0", version: "1.0", severity: types.SeverityHigh},
	"VersionTLS11": {name: "TLS 1.1", version: "1.1", severity: types.SeverityHigh},
	"VersionTLS12": {name: "TLS 1.2", version: "1.2", severity: types.SeverityInfo},
	"VersionTLS13": {name: "TLS 1.3", version: "1.3", severity: types.SeverityInfo},
	"VersionSSL30": {name: "SSL 3.0", version: "3.0", severity: types.SeverityHigh},
}

func (s *GoScanner) detectCryptoTLS(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/tls")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// Look for tls.VersionTLSxx references in struct field assignments
	// Pattern: MinVersion: tls.VersionTLS12 or MaxVersion: tls.VersionTLS13
	s.walkForTLSVersions(root, content, alias, path, &findings)

	return findings
}

func (s *GoScanner) walkForTLSVersions(node *sitter.Node, content []byte, alias, path string, findings *[]types.Finding) {
	if node == nil {
		return
	}

	// Look for selector_expression nodes like tls.VersionTLS12
	if node.Type() == "selector_expression" {
		operand := node.ChildByFieldName("operand")
		field := node.ChildByFieldName("field")
		if operand != nil && field != nil {
			if operand.Content(content) == alias {
				constName := field.Content(content)
				if info, ok := tlsVersionConstants[constName]; ok {
					ruleID := fmt.Sprintf("cbom-go-tls-%s", strings.ToLower(strings.ReplaceAll(info.version, ".", "")))
					*findings = append(*findings, types.Finding{
						ID:         nextFindingID(),
						AssetType:  types.AssetProtocol,
						Name:       info.name,
						Location:   scanner.NodeLocation(node, path, content),
						Severity:   info.severity,
						Confidence: types.ConfidenceHigh,
						Properties: types.CryptoProperties{
							ProtocolType:    "tls",
							ProtocolVersion: info.version,
						},
						Description: fmt.Sprintf("TLS version %s via %s.%s", info.version, alias, constName),
						RuleID:      ruleID,
						Pass:        1,
					})
				}
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			s.walkForTLSVersions(child, content, alias, path, findings)
		}
	}
}

// ---------------------------------------------------------------------------
// crypto/x509 detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectCryptoX509(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "crypto/x509")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// x509.ParseCertificate, x509.ParseCertificates, x509.ParsePKCS8PrivateKey, etc.
	certFuncs := []string{"ParseCertificate", "ParseCertificates", "ParseCertificatePEM"}
	for _, funcName := range certFuncs {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetCertificate,
				Name:       "X.509",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					CertificateFormat: "X.509",
				},
				Description: fmt.Sprintf("X.509 certificate parsing via %s.%s()", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-x509-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// tjfoc/gmsm SM2 detection (Chinese national EC scheme, quantum-vulnerable)
// ---------------------------------------------------------------------------

// sm2Functions maps SM2 package function names to the crypto-function role and
// primitive they represent. Detection is gated on the gmsm/sm2 import alias, so
// a bare GenerateKey/Sign/Encrypt call in unrelated code is never flagged.
var sm2Functions = map[string]struct {
	cryptoFn  string
	primitive string
}{
	"GenerateKey": {cryptoFn: "generate", primitive: "pke"},
	"Sign":        {cryptoFn: "sign", primitive: "signature"},
	"Verify":      {cryptoFn: "verify", primitive: "signature"},
	"Encrypt":     {cryptoFn: "encrypt", primitive: "pke"},
	"Decrypt":     {cryptoFn: "decrypt", primitive: "pke"},
}

func (s *GoScanner) detectSM2(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	// tjfoc/gmsm is the de-facto Go SM2 implementation. Match its sm2 subpackage.
	alias := aliasFor(imports, "github.com/tjfoc/gmsm/sm2")
	if alias == "" {
		return nil
	}

	var findings []types.Finding
	qi := quantum.GetInfo("sm2")

	for funcName, info := range sm2Functions {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "SM2",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:        info.primitive,
					AlgorithmFamily:  "sm2",
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
					CryptoFunctions:  []string{info.cryptoFn},
				},
				Description: fmt.Sprintf("SM2 %s via %s.%s() — quantum-vulnerable", info.cryptoFn, alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-sm2-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// golang.org/x/crypto detection
// ---------------------------------------------------------------------------

func (s *GoScanner) detectXCrypto(root *sitter.Node, path string, content []byte, imports map[string]string, cp *ConstPropagator) []types.Finding {
	var findings []types.Finding

	// ChaCha20-Poly1305
	findings = append(findings, s.detectChaCha20Poly1305(root, path, content, imports)...)

	// NaCl
	findings = append(findings, s.detectNaCl(root, path, content, imports)...)

	// Argon2
	findings = append(findings, s.detectArgon2(root, path, content, imports)...)

	// bcrypt
	findings = append(findings, s.detectBcrypt(root, path, content, imports, cp)...)

	// scrypt
	findings = append(findings, s.detectScrypt(root, path, content, imports)...)

	// SSH
	findings = append(findings, s.detectSSH(root, path, content, imports)...)

	// HKDF
	findings = append(findings, s.detectHKDF(root, path, content, imports)...)

	return findings
}

func (s *GoScanner) detectChaCha20Poly1305(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "golang.org/x/crypto/chacha20poly1305")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// chacha20poly1305.New(key), chacha20poly1305.NewX(key)
	for _, funcName := range []string{"New", "NewX"} {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("chacha20")
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       "ChaCha20-Poly1305",
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
				Description: fmt.Sprintf("ChaCha20-Poly1305 AEAD via %s.%s()", alias, funcName),
				RuleID:      "cbom-go-chacha20poly1305-new",
				Pass:        1,
			})
		}
	}

	return findings
}

func (s *GoScanner) detectNaCl(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	var findings []types.Finding

	// nacl/box
	boxAlias := aliasFor(imports, "golang.org/x/crypto/nacl/box")
	if boxAlias != "" {
		for _, funcName := range []string{"Seal", "Open", "GenerateKey"} {
			for _, callNode := range s.findSelectorCalls(root, content, boxAlias, funcName) {
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       "NaCl-Box",
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:       "ae",
						AlgorithmFamily: "nacl",
						CryptoFunctions: []string{"encrypt"},
					},
					Description: fmt.Sprintf("NaCl box via %s.%s()", boxAlias, funcName),
					RuleID:      "cbom-go-nacl-box",
					Pass:        1,
				})
			}
		}
	}

	// nacl/secretbox
	secretboxAlias := aliasFor(imports, "golang.org/x/crypto/nacl/secretbox")
	if secretboxAlias != "" {
		for _, funcName := range []string{"Seal", "Open"} {
			for _, callNode := range s.findSelectorCalls(root, content, secretboxAlias, funcName) {
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetAlgorithm,
					Name:       "NaCl-SecretBox",
					Location:   scanner.NodeLocation(callNode, path, content),
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceHigh,
					Properties: types.CryptoProperties{
						Primitive:       "ae",
						AlgorithmFamily: "nacl",
						CryptoFunctions: []string{"encrypt"},
					},
					Description: fmt.Sprintf("NaCl secretbox via %s.%s()", secretboxAlias, funcName),
					RuleID:      "cbom-go-nacl-secretbox",
					Pass:        1,
				})
			}
		}
	}

	return findings
}

func (s *GoScanner) detectArgon2(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "golang.org/x/crypto/argon2")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// argon2.IDKey(...), argon2.Key(...)
	for _, funcName := range []string{"IDKey", "Key"} {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
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
					CryptoFunctions: []string{"keydrive"},
				},
				Description: fmt.Sprintf("Argon2 key derivation via %s.%s()", alias, funcName),
				RuleID:      "cbom-go-argon2-idkey",
				Pass:        1,
			})
		}
	}

	return findings
}

func (s *GoScanner) detectBcrypt(root *sitter.Node, path string, content []byte, imports map[string]string, cp *ConstPropagator) []types.Finding {
	alias := aliasFor(imports, "golang.org/x/crypto/bcrypt")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// bcrypt.GenerateFromPassword(password, cost)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "GenerateFromPassword") {
		// Try to extract cost (2nd argument, index 1)
		severity := types.SeverityInfo
		argsNode := s.findChildByType(callNode, "argument_list")
		if argsNode != nil {
			cost, _ := resolveNthArg(argsNode, 1, content, cp)
			if cost != "" {
				costVal, err := strconv.Atoi(cost)
				if err == nil {
					if s, _ := kdf.CheckKDFIterations("bcrypt", costVal); s != types.SeverityInfo {
						severity = s
					}
				}
			}
		}
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "bcrypt",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   severity,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "kdf",
				AlgorithmFamily: "bcrypt",
				CryptoFunctions: []string{"passwordhash"},
			},
			Description: fmt.Sprintf("bcrypt password hashing via %s.GenerateFromPassword()", alias),
			RuleID:      "cbom-go-bcrypt-generatefrompassword",
			Pass:        1,
		})
	}

	// bcrypt.CompareHashAndPassword
	for _, callNode := range s.findSelectorCalls(root, content, alias, "CompareHashAndPassword") {
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "bcrypt",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "kdf",
				AlgorithmFamily: "bcrypt",
				CryptoFunctions: []string{"passwordhash"},
			},
			Description: fmt.Sprintf("bcrypt password verification via %s.CompareHashAndPassword()", alias),
			RuleID:      "cbom-go-bcrypt-comparehash",
			Pass:        1,
		})
	}

	return findings
}

func (s *GoScanner) detectScrypt(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "golang.org/x/crypto/scrypt")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// scrypt.Key(password, salt, N, r, p, keyLen)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "Key") {
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "scrypt",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "kdf",
				AlgorithmFamily: "scrypt",
				CryptoFunctions: []string{"keydrive"},
			},
			Description: fmt.Sprintf("scrypt key derivation via %s.Key()", alias),
			RuleID:      "cbom-go-scrypt-key",
			Pass:        1,
		})
	}

	return findings
}

func (s *GoScanner) detectSSH(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "golang.org/x/crypto/ssh")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// ssh.ParsePrivateKey, ssh.ParseAuthorizedKey, ssh.NewClientConn, etc.
	sshFuncs := []string{"ParsePrivateKey", "ParseAuthorizedKey", "NewClientConn", "Dial"}
	for _, funcName := range sshFuncs {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetProtocol,
				Name:       "SSH",
				Location:   scanner.NodeLocation(callNode, path, content),
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType: "ssh",
				},
				Description: fmt.Sprintf("SSH usage via %s.%s()", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-ssh-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

func (s *GoScanner) detectHKDF(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasFor(imports, "golang.org/x/crypto/hkdf")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// hkdf.New(hash, secret, salt, info)
	for _, callNode := range s.findSelectorCalls(root, content, alias, "New") {
		findings = append(findings, types.Finding{
			ID:         nextFindingID(),
			AssetType:  types.AssetAlgorithm,
			Name:       "HKDF",
			Location:   scanner.NodeLocation(callNode, path, content),
			Severity:   types.SeverityInfo,
			Confidence: types.ConfidenceHigh,
			Properties: types.CryptoProperties{
				Primitive:       "kdf",
				AlgorithmFamily: "hkdf",
				CryptoFunctions: []string{"keydrive"},
			},
			Description: fmt.Sprintf("HKDF key derivation via %s.New()", alias),
			RuleID:      "cbom-go-hkdf-new",
			Pass:        1,
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Schnorr signatures (BIP-340 / Taproot) detection
// ---------------------------------------------------------------------------
//
// Detected libraries (import-anchored, never bare-word "schnorr"):
//   - github.com/btcsuite/btcd/btcec/v2/schnorr        (btcec/schnorr)
//   - github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr
//   - github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr/musig2
// All ship the package as a final "schnorr" segment, so aliasForAny matches
// on that segment without a long path list.

func (s *GoScanner) detectSchnorr(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasForAny(imports, "schnorr")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// schnorr.Sign / schnorr.Verify / schnorr.NewSignature / schnorr.ParseSignature
	calls := map[string]string{
		"Sign":           "sign",
		"Verify":         "verify",
		"NewSignature":   "sign",
		"ParseSignature": "verify",
	}
	for funcName, fn := range calls {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("schnorr")
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
				Description: fmt.Sprintf("Schnorr (BIP-340) signature via %s.%s() — quantum-vulnerable", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-schnorr-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// BLS / BLS12-381 signature detection (Ethereum eth2)
// ---------------------------------------------------------------------------
//
// Detected libraries (import-anchored):
//   - github.com/kilic/bls12-381                 (alias "bls12381")
//   - github.com/herumi/bls-eth-go-binary/bls    (alias "bls")
//   - github.com/prysmaticlabs/prysm/.../crypto/bls
//   - github.com/protolambda/bls12-381-util
// Matching is on the final path segment ("bls12-381", "bls12381", "bls"),
// which is import-anchored — never a bare "bls" word in comments/identifiers.

func (s *GoScanner) detectBLS(root *sitter.Node, path string, content []byte, imports map[string]string) []types.Finding {
	alias := aliasForAny(imports, "bls12-381", "bls12381", "bls")
	if alias == "" {
		return nil
	}

	var findings []types.Finding

	// Sign / Verify / aggregate / key-gen entry points across the common libs.
	calls := map[string]string{
		"Sign":                "sign",
		"Verify":              "verify",
		"SignatureFromBytes":  "verify",
		"AggregateSignatures": "sign",
		"RandKey":             "generate",
		"NewG1":               "generate",
		"NewG2":               "generate",
	}
	for funcName, fn := range calls {
		for _, callNode := range s.findSelectorCalls(root, content, alias, funcName) {
			qi := quantum.GetInfo("bls")
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
				Description: fmt.Sprintf("BLS12-381 pairing-based signature via %s.%s() — quantum-vulnerable", alias, funcName),
				RuleID:      fmt.Sprintf("cbom-go-bls-%s", strings.ToLower(funcName)),
				Pass:        1,
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Tree-sitter helpers
// ---------------------------------------------------------------------------

// findSelectorCalls finds call_expression nodes where the function is a
// selector_expression matching alias.funcName (e.g., aes.NewCipher).
func (s *GoScanner) findSelectorCalls(root *sitter.Node, content []byte, alias, funcName string) []*sitter.Node {
	var nodes []*sitter.Node
	s.walkForSelectorCalls(root, content, alias, funcName, &nodes)
	return nodes
}

func (s *GoScanner) walkForSelectorCalls(node *sitter.Node, content []byte, alias, funcName string, nodes *[]*sitter.Node) {
	if node == nil {
		return
	}

	if node.Type() == "call_expression" {
		fnNode := node.ChildByFieldName("function")
		if fnNode != nil && fnNode.Type() == "selector_expression" {
			operand := fnNode.ChildByFieldName("operand")
			field := fnNode.ChildByFieldName("field")
			if operand != nil && field != nil {
				if operand.Content(content) == alias && field.Content(content) == funcName {
					*nodes = append(*nodes, node)
				}
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			s.walkForSelectorCalls(child, content, alias, funcName, nodes)
		}
	}
}

// findChildByType finds the first direct child of a given node type.
func (s *GoScanner) findChildByType(node *sitter.Node, nodeType string) *sitter.Node {
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

// ---------------------------------------------------------------------------
// Argument resolution helpers
// ---------------------------------------------------------------------------

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
			case "interpreted_string_literal", "raw_string_literal":
				return unquoteGoString(child.Content(content)), types.ConfidenceHigh
			case "int_literal":
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

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

// unquoteGoString removes surrounding quotes from a Go string literal.
func unquoteGoString(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	// Interpreted string literal: "..."
	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1]
	}

	// Raw string literal: `...`
	if raw[0] == '`' && raw[len(raw)-1] == '`' {
		return raw[1 : len(raw)-1]
	}

	return raw
}
