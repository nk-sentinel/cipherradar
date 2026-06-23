// Package keysize backfills CryptoProperties.KeySize on findings where scanners
// encoded bit strength in Name or curve identifiers but did not populate KeySize.
package keysize

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// curveBits maps normalized curve identifiers to classical bit strength.
var curveBits = map[string]int{
	"secp256r1": 256, "p-256": 256, "p256": 256, "prime256v1": 256, "nistp256": 256,
	"secp384r1": 384, "p-384": 384, "p384": 384, "nistp384": 384,
	"secp521r1": 521, "p-521": 521, "p521": 521, "nistp521": 521,
	"secp256k1": 256,
	"x25519": 256, "curve25519": 256, "ed25519": 256,
	"x448": 448,
}

// keySizedFamilies are algorithm families where a numeric token segment is key width in bits.
var keySizedFamilies = map[string]bool{
	"aes": true, "rsa": true, "camellia": true, "aria": true, "blowfish": true,
	"rc2": true, "rc4": true, "rc5": true, "des": true, "3des": true,
	"dh": true, "dsa": true, "rsaes": true, "rsassa": true,
}

var (
	pCurveRe     = regexp.MustCompile(`(?i)\bp-?(256|384|521)\b`)
	curveTokenRe = regexp.MustCompile(`(?i)(secp256r1|secp384r1|secp521r1|secp256k1|prime256v1|curve25519|x25519|ed25519|x448)`)
	phpBitsRe    = regexp.MustCompile(`(?i)['"]?private_key_bits['"]?\s*=>\s*(\d+)`)
)

// CurveBits returns the classical bit strength for a named elliptic curve, or 0.
func CurveBits(curve string) int {
	norm := normalizeCurve(curve)
	if bits, ok := curveBits[norm]; ok {
		return bits
	}
	return 0
}

func normalizeCurve(curve string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(curve)))
}

// InferFromToken extracts key size from an algorithm name or primitive token
// (e.g. "AES-256-GCM" → 256, "RSA-2048" → 2048). Returns 0 for hashes and unknown tokens.
func InferFromToken(token string) int {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0
	}
	if isHashToken(token) {
		return 0
	}

	parts := splitToken(token)
	for i := 1; i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || !isPlausibleKeySize(n) {
			continue
		}
		family := strings.ToLower(parts[i-1])
		if keySizedFamilies[family] {
			return n
		}
	}

	if n := inferPCurve(token); n > 0 {
		return n
	}
	return 0
}

// InferFromCurveName scans a display name for known curve identifiers.
func InferFromCurveName(name string) int {
	if m := curveTokenRe.FindStringSubmatch(name); m != nil {
		return CurveBits(m[1])
	}
	return inferPCurve(name)
}

func inferPCurve(s string) int {
	m := pCurveRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func isHashToken(token string) bool {
	upper := strings.ToUpper(token)
	switch {
	case strings.HasPrefix(upper, "SHA-"), strings.HasPrefix(upper, "SHA2"), strings.HasPrefix(upper, "SHA3"):
		return true
	case strings.HasPrefix(upper, "SHA"), strings.HasPrefix(upper, "MD2"), strings.HasPrefix(upper, "MD4"), strings.HasPrefix(upper, "MD5"):
		return true
	case strings.HasPrefix(upper, "HMAC-"), strings.HasPrefix(upper, "HMAC"):
		return true
	case strings.HasPrefix(upper, "BLAKE"), strings.HasPrefix(upper, "RIPEMD"), strings.HasPrefix(upper, "WHIRLPOOL"):
		return true
	case strings.HasPrefix(upper, "SM3"):
		return true
	}
	parts := splitToken(token)
	if len(parts) >= 2 {
		f := strings.ToLower(parts[0])
		if f == "sha" || f == "md5" || f == "md4" || f == "md2" {
			return true
		}
	}
	return false
}

func splitToken(token string) []string {
	repl := strings.NewReplacer("/", "-", "_", "-", " ", "-")
	normalized := repl.Replace(token)
	var parts []string
	for _, p := range strings.Split(normalized, "-") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func isPlausibleKeySize(n int) bool {
	switch n {
	case 56, 64, 80, 112, 128, 160, 168, 192, 224, 256, 384, 512, 521, 1024, 2048, 3072, 4096, 8192:
		return true
	default:
		return false
	}
}

// ParsePHPPrivateKeyBits extracts private_key_bits from an openssl_pkey_new config snippet.
func ParsePHPPrivateKeyBits(configText string) int {
	m := phpBitsRe.FindStringSubmatch(configText)
	if m == nil || len(m) < 2 {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// Enrich backfills KeySize on algorithm findings from Name, AlgorithmPrimitive, and curves.
func Enrich(findings []types.Finding) {
	for i := range findings {
		enrichOne(&findings[i])
	}
}

func enrichOne(f *types.Finding) {
	if f.Properties.KeySize > 0 {
		return
	}
	if f.AssetType != types.AssetAlgorithm {
		return
	}
	if f.Properties.Primitive == "hash" {
		return
	}

	for _, tok := range []string{f.Name, f.Properties.AlgorithmPrimitive} {
		if n := InferFromToken(tok); n > 0 {
			f.Properties.KeySize = n
			return
		}
	}
	if n := InferFromCurveName(f.Name); n > 0 {
		f.Properties.KeySize = n
		return
	}
	if n := InferFromCurveName(f.Properties.AlgorithmPrimitive); n > 0 {
		f.Properties.KeySize = n
	}
}
