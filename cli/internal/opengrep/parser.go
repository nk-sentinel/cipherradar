package opengrep

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// opengrepOutput represents the top-level JSON output from OpenGrep/Semgrep.
type opengrepOutput struct {
	Results []opengrepResult `json:"results"`
	Errors  []opengrepError  `json:"errors"`
}

// opengrepResult represents a single result from OpenGrep JSON output.
type opengrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   opengrepPos     `json:"start"`
	End     opengrepPos     `json:"end"`
	Extra   opengrepExtra   `json:"extra"`
}

// opengrepPos represents a position in a file.
type opengrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

// opengrepExtra holds the metadata for an OpenGrep result.
type opengrepExtra struct {
	Message  string                     `json:"message"`
	Severity string                     `json:"severity"`
	Metadata opengrepMetadata           `json:"metadata"`
	Lines    string                     `json:"lines"`
	Metavars map[string]opengrepMetavar `json:"metavars,omitempty"`
}

// opengrepMetavar captures the literal text bound to a pattern metavariable.
// OpenGrep emits a richer object per metavar; we only need abstract_content
// (the captured source text) for cbom-primitive-from-metavar resolution.
type opengrepMetavar struct {
	AbstractContent string `json:"abstract_content"`
}

// opengrepMetadata holds CBOM-specific metadata from rule annotations.
//
// DefaultEnabled uses *bool so we can distinguish "unset" (nil) from
// "explicitly false". Portal-synced rules pre-dating this field are treated
// as default_enabled: true (see mapDefaultEnabled).
//
// CbomPrimitive / CbomPrimitiveFromMetavar / CbomPrimitiveFallback drive the
// canonical-token resolution implemented in resolveAlgorithmPrimitive:
//   1. static cbom-primitive wins (literal canonical token)
//   2. else look up cbom-primitive-from-metavar (e.g. "$ALGO") against
//      extra.metavars and canonicalize the captured text
//   3. else use cbom-primitive-fallback (used when the metavar isn't a literal)
type opengrepMetadata struct {
	CbomAssetType            string `json:"cbom-asset-type"`
	Confidence               string `json:"confidence"`
	QuantumRelevant          bool   `json:"quantum-relevant"`
	Category                 string `json:"category"`
	Maturity                 string `json:"maturity"`
	NoiseRisk                string `json:"noise_risk"`
	DefaultEnabled           *bool  `json:"default_enabled"`
	CbomPrimitive            string `json:"cbom-primitive"`
	CbomPrimitiveFromMetavar string `json:"cbom-primitive-from-metavar"`
	CbomPrimitiveFallback    string `json:"cbom-primitive-fallback"`
	CbomLibrary              string `json:"cbom-library"`
}

// opengrepError represents an error reported by OpenGrep.
type opengrepError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

// ParseResults parses OpenGrep JSON output into CipherRadar findings.
// All returned findings have Pass = 2.
func ParseResults(jsonData []byte) ([]types.Finding, error) {
	if len(jsonData) == 0 {
		return nil, nil
	}

	var output opengrepOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		return nil, fmt.Errorf("invalid opengrep JSON: %w", err)
	}

	// Bug 6: when opengrep refused to load any rules / scan any paths it
	// returns results=[] and a populated errors[] — silently returning 0
	// findings used to mask broken rule files. Surface the messages.
	if len(output.Results) == 0 && len(output.Errors) > 0 {
		msgs := make([]string, 0, len(output.Errors))
		for _, e := range output.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("opengrep produced no results, %d errors: %s",
			len(output.Errors), strings.Join(msgs, "; "))
	}

	findings := make([]types.Finding, 0, len(output.Results))
	for _, r := range output.Results {
		canonicalID := stripCheckIDNamespace(r.CheckID)
		f := types.Finding{
			RuleID:         canonicalID,
			Pass:           2,
			Description:    r.Extra.Message,
			Severity:       mapSeverity(r.Extra.Severity),
			Confidence:     mapConfidence(r.Extra.Metadata.Confidence),
			AssetType:      mapAssetType(r.Extra.Metadata.CbomAssetType),
			Category:       mapCategory(r.Extra.Metadata.Category),
			Maturity:       mapMaturity(r.Extra.Metadata.Maturity),
			NoiseRisk:      mapNoiseRisk(r.Extra.Metadata.NoiseRisk),
			DefaultEnabled: mapDefaultEnabled(r.Extra.Metadata.DefaultEnabled),
			Location: types.Location{
				File:      r.Path,
				StartLine: r.Start.Line,
				StartCol:  r.Start.Col,
				EndLine:   r.End.Line,
				EndCol:    r.End.Col,
				Snippet:   r.Extra.Lines,
			},
		}

		// Derive a name from the check_id if possible.
		f.Name = deriveNameFromCheckID(canonicalID)

		// Resolve the canonical algorithm primitive token from rule metadata
		// and any captured metavars. See opengrepMetadata doc for the precedence.
		f.Properties.AlgorithmPrimitive = resolveAlgorithmPrimitive(&r.Extra)
		f.Properties.Library = strings.TrimSpace(r.Extra.Metadata.CbomLibrary)

		findings = append(findings, f)
	}

	return findings, nil
}

// mapSeverity maps OpenGrep severity strings to CipherRadar Severity.
func mapSeverity(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return types.SeverityHigh
	case "WARNING":
		return types.SeverityMedium
	case "INFO":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// mapConfidence maps OpenGrep confidence strings to CipherRadar Confidence.
func mapConfidence(s string) types.Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return types.ConfidenceHigh
	case "medium":
		return types.ConfidenceMedium
	case "low":
		return types.ConfidenceLow
	default:
		return types.ConfidenceMedium
	}
}

// mapAssetType maps OpenGrep cbom-asset-type metadata to CipherRadar AssetType.
func mapAssetType(s string) types.AssetType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "algorithm":
		return types.AssetAlgorithm
	case "protocol":
		return types.AssetProtocol
	case "certificate":
		return types.AssetCertificate
	case "related-crypto-material":
		return types.AssetRelatedCryptoMaterial
	default:
		if s != "" {
			return types.AssetType(s)
		}
		return types.AssetAlgorithm
	}
}

// mapCategory maps the YAML "category" field to a types.Category. An unset or
// unrecognized value defaults to CategorySecurity (conservative: include in
// default scan). Rule authors should set this explicitly.
func mapCategory(s string) types.Category {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "inventory":
		return types.CategoryInventory
	case "security":
		return types.CategorySecurity
	default:
		return types.CategorySecurity
	}
}

// mapMaturity maps the YAML "maturity" field to a types.Maturity. An unset or
// unrecognized value defaults to MaturityStable (forward-compat: portal-synced
// rules pre-dating this field are treated as stable production rules).
func mapMaturity(s string) types.Maturity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "experimental":
		return types.MaturityExperimental
	case "stable":
		return types.MaturityStable
	case "deprecated":
		return types.MaturityDeprecated
	default:
		return types.MaturityStable
	}
}

// mapNoiseRisk maps the YAML "noise_risk" field to a types.NoiseRisk. An unset
// or unrecognized value defaults to NoiseRiskLow.
func mapNoiseRisk(s string) types.NoiseRisk {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return types.NoiseRiskLow
	case "med", "medium":
		return types.NoiseRiskMedium
	case "high":
		return types.NoiseRiskHigh
	default:
		return types.NoiseRiskLow
	}
}

// mapDefaultEnabled maps the YAML "default_enabled" field to a bool. nil (unset)
// maps to true for forward-compat with rules authored before this field existed.
func mapDefaultEnabled(b *bool) bool {
	if b == nil {
		return true
	}
	return *b
}

// stripCheckIDNamespace removes the directory-derived namespace prefix that
// OpenGrep adds when invoked with --config <dir>. The check_id format is
// "<dot.separated.namespace>.cbom-<lang>-<id>"; real rule IDs use dashes
// (no dots), so taking everything after the last dot is safe.
//
// When OpenGrep is invoked with per-file --config <file>, the prefix is
// absent and this is a no-op.
func stripCheckIDNamespace(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}

// deriveNameFromCheckID attempts to extract a human-readable name from the check_id.
// For example, "cbom-python-hardcoded-key" becomes "hardcoded-key".
//
// Per-language prefixes are listed longest-first so the bare "cbom-" fallback
// only matches when no language prefix applies.
func deriveNameFromCheckID(checkID string) string {
	// Strip common prefixes.
	name := checkID
	for _, prefix := range []string{
		"cbom-javascript-",
		"cbom-python-",
		"cbom-kotlin-",
		"cbom-swift-",
		"cbom-java-",
		"cbom-ruby-",
		"cbom-rust-",
		"cbom-dart-",
		"cbom-csharp-",
		"cbom-cpp-",
		"cbom-php-",
		"cbom-js-",
		"cbom-go-",
		"cbom-",
	} {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			break
		}
	}
	return name
}

// resolveAlgorithmPrimitive applies the cbom-primitive resolution precedence
// (static -> metavar -> fallback) and returns a canonicalized algorithm token,
// or "" when no source provides one.
//
// Precedence:
//  1. cbom-primitive (static literal token from rule metadata)
//  2. metavar lookup: cbom-primitive-from-metavar names a metavar
//     (e.g. "$ALGO"); resolve via extra.metavars[<name>].abstract_content,
//     then canonicalize. Skipped if the captured text doesn't look like an
//     algorithm token (e.g. it's a variable reference).
//  3. cbom-primitive-fallback (used when the metavar route fails)
//
// All sources are run through canonicalizePrimitive once more so callers
// get a consistent representation (e.g. "AES-256-GCM", not "AES_256_GCM").
// If the chosen value can't be canonicalized but is non-empty, the raw
// trimmed value is returned to avoid silently dropping rule intent.
func resolveAlgorithmPrimitive(extra *opengrepExtra) string {
	md := extra.Metadata

	// 1. Static primitive wins.
	if v := strings.TrimSpace(md.CbomPrimitive); v != "" {
		if c := canonicalizePrimitive(v); c != "" {
			return c
		}
		return v
	}

	// 2. Metavar lookup.
	if key := strings.TrimSpace(md.CbomPrimitiveFromMetavar); key != "" {
		if mv, ok := extra.Metavars[key]; ok {
			if c := canonicalizePrimitive(mv.AbstractContent); c != "" {
				return c
			}
		}
	}

	// 3. Fallback.
	if v := strings.TrimSpace(md.CbomPrimitiveFallback); v != "" {
		if c := canonicalizePrimitive(v); c != "" {
			return c
		}
		return v
	}

	return ""
}

// canonicalizePrimitive normalizes an algorithm/protocol/library token into
// the canonical form used in CBOM output (uppercase, hyphen-separated). It
// returns "" when the input doesn't look like a recognised crypto token so
// callers can fall back to a rule-provided default.
//
// Examples:
//   md5                       -> MD5
//   sha1, sha-1               -> SHA-1
//   sha256, sha-256           -> SHA-256
//   sha3_256                  -> SHA3-256
//   AES/GCM/NoPadding         -> AES-GCM
//   AES_256_GCM               -> AES-256-GCM
//   TLSv1.0, tls_version_1_3  -> TLS-1.0, TLS-1.3
//   PBKDF2WithHmacSHA256      -> PBKDF2-HMAC-SHA256
//   some_random_var           -> "" (caller uses fallback)
func canonicalizePrimitive(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	up := strings.ToUpper(s)

	// Cipher-spec wrappers: AES/ECB/PKCS5Padding -> AES-ECB (mode wins,
	// padding dropped — padding is exposed separately in CryptoProperties.Padding).
	if strings.Contains(up, "/") {
		parts := strings.Split(up, "/")
		if len(parts) >= 2 && isModeToken(parts[1]) {
			return parts[0] + "-" + parts[1]
		}
		up = parts[0]
	}

	// Normalize separators (underscore/dot -> hyphen).
	up = strings.ReplaceAll(up, "_", "-")

	// TLS / SSL version normalization. Handle these before the generic prefix
	// path so "TLSV1.0" / "TLS-VERSION-1-3" become TLS-1.x. The CBOM
	// convention is dotted minor versions (TLS-1.0, TLS-1.3); the underscore
	// normalizer above will have collapsed "1_3" -> "1-3", so flip the
	// version-internal hyphen back to a dot.
	formatVersion := func(prefix, ver string) string {
		ver = strings.ReplaceAll(ver, "-", ".")
		return prefix + "-" + ver
	}
	if strings.HasPrefix(up, "TLSV") {
		return formatVersion("TLS", strings.TrimPrefix(up, "TLSV"))
	}
	if strings.HasPrefix(up, "TLS-VERSION-") {
		return formatVersion("TLS", strings.TrimPrefix(up, "TLS-VERSION-"))
	}
	if strings.HasPrefix(up, "SSLV") {
		return formatVersion("SSL", strings.TrimPrefix(up, "SSLV"))
	}

	// PBKDF2WithHmacSHA256 -> PBKDF2-HMAC-SHA256 (must run before the
	// SHA<n> normalizer; we keep the digest as "SHA<n>" with no hyphen
	// to match the CBOM convention for PBKDF2-HMAC-* tokens).
	if strings.HasPrefix(up, "PBKDF2WITHHMAC") {
		rest := strings.TrimPrefix(up, "PBKDF2WITHHMAC")
		rest = strings.TrimPrefix(rest, "-")
		if rest == "" {
			return "PBKDF2-HMAC"
		}
		return "PBKDF2-HMAC-" + rest
	}

	// Bare SHA + digits: SHA256 -> SHA-256, SHA384 -> SHA-384, SHA512 -> SHA-512.
	// SHA3 is handled in the next branch.
	if strings.HasPrefix(up, "SHA") && !strings.HasPrefix(up, "SHA-") &&
		!strings.HasPrefix(up, "SHA3") && !strings.HasPrefix(up, "SHAKE") {
		rest := up[3:]
		if _, err := strconv.Atoi(rest); err == nil {
			return "SHA-" + rest
		}
		if rest == "1" {
			return "SHA-1"
		}
	}
	if up == "SHA1" {
		return "SHA-1"
	}

	// SHA3 family: SHA3256 (unlikely) / SHA3-256 are both OK; the underscore
	// normalization above handles sha3_256 -> SHA3-256.
	if strings.HasPrefix(up, "SHA3") && !strings.HasPrefix(up, "SHA3-") && len(up) > 4 {
		rest := up[4:]
		if _, err := strconv.Atoi(rest); err == nil {
			return "SHA3-" + rest
		}
	}

	// Argon2 family.
	switch up {
	case "ARGON2ID":
		return "ARGON2ID"
	case "ARGON2I":
		return "ARGON2I"
	case "ARGON2":
		return "ARGON2"
	}

	if !looksLikePrimitive(up) {
		return ""
	}
	return up
}

// isModeToken reports whether s names a block-cipher mode of operation.
// Used by canonicalizePrimitive to detect cipher specs like "AES/GCM/...".
func isModeToken(s string) bool {
	switch strings.ToUpper(s) {
	case "ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "CCM", "XTS", "SIV", "KW":
		return true
	}
	return false
}

// looksLikePrimitive accepts uppercase tokens that begin with a known
// algorithm/protocol prefix (or are an exact whitelist match). This filters
// out captured-but-non-literal metavar contents like "my_variable" while
// keeping common shapes such as "AES-256", "RSA", "MD5", "TLS-1.3".
func looksLikePrimitive(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	if strings.ContainsAny(s, " \t\n\"'`()=") {
		return false
	}
	prefixes := []string{
		"MD", "SHA", "SHAKE", "AES", "DES", "3DES", "RC", "RSA", "DSA", "DH",
		"ECDH", "ECDSA", "ED", "X25519", "X448", "CURVE", "SECP",
		"BLOWFISH", "CAMELLIA", "CAST", "IDEA", "SEED", "SERPENT", "SM3",
		"SM4", "TWOFISH", "ARIA", "CHACHA", "XSALSA", "POLY1305", "BLAKE",
		"RIPEMD", "TIGER", "WHIRLPOOL", "KECCAK", "GOST", "SKEIN",
		"PBKDF", "HKDF", "SCRYPT", "BCRYPT", "ARGON", "HMAC", "GMAC", "CMAC",
		"TLS", "SSL", "SSH", "IPSEC", "DTLS",
		"KYBER", "ML-KEM", "ML-DSA", "DILITHIUM", "FALCON", "SPHINCS",
		"XMSS", "LMS", "HSS", "NTRU", "HQC",
		"PKCS", "OAEP", "FERNET", "CRYPTO-LIBRARY-IMPORT",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
