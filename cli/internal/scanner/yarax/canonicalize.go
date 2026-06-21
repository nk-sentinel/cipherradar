package yarax

import (
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// yaraMeta is the normalized projection of a YARA rule's `meta:` block
// after JSON values from `yr scan --print-meta` have been coerced to
// the strings we actually care about.
//
// Field names match the YARA meta keys (cbom_primitive, cbom_asset_type,
// ...) the in-tree ruleset under scanner/yara-rules/ uses. The same
// canonical-token vocabulary is shared with the OpenGrep ruleset
// (`cbom-primitive` / `cbom-asset-type` / ...) — see
// `scanner/yara-rules/README.md`.
//
// DefaultEnabled is a bool because the parser coerces the
// string-encoded `"true"` / `"false"` YARA meta value at parse time;
// the wire-side representation is a string for consistency with the
// OpenGrep YAML rules, but downstream consumers want a bool.
type yaraMeta struct {
	Description     string
	CbomPrimitive   string
	CbomAssetType   string
	CbomLibrary     string
	Category        string
	Maturity        string
	NoiseRisk       string
	DefaultEnabled  bool
}

// parseMeta extracts the cradar-canonical metadata fields from YARA-X's
// raw `meta` map. YARA-X emits per-key values typed as string, int, or
// bool; we accept the string form for every field (DefaultEnabled also
// accepts a real bool, defensively) and ignore anything else.
//
// A missing or empty key is treated as unset — callers fall back to
// per-field defaults (mapMaturity etc.) the same way the OpenGrep
// parser does.
//
// DefaultEnabled defaults to true when unset, matching mapDefaultEnabled
// in cli/internal/opengrep/parser.go (forward-compat for rules authored
// before the field existed).
func parseMeta(raw map[string]any) yaraMeta {
	m := yaraMeta{DefaultEnabled: true}
	if raw == nil {
		return m
	}
	m.Description = metaStr(raw, "description")
	m.CbomPrimitive = metaStr(raw, "cbom_primitive")
	m.CbomAssetType = metaStr(raw, "cbom_asset_type")
	m.CbomLibrary = metaStr(raw, "cbom_library")
	m.Category = metaStr(raw, "category")
	m.Maturity = metaStr(raw, "maturity")
	m.NoiseRisk = metaStr(raw, "noise_risk")

	if v, ok := raw["default_enabled"]; ok {
		switch x := v.(type) {
		case bool:
			m.DefaultEnabled = x
		case string:
			switch strings.ToLower(strings.TrimSpace(x)) {
			case "false", "0", "no":
				m.DefaultEnabled = false
			case "true", "1", "yes", "":
				m.DefaultEnabled = true
			}
		}
	}

	return m
}

// metaStr returns the trimmed string value of meta[key], or "" if the
// key is missing, nil, or typed as something other than string. YARA-X
// JSON values for meta are stringly typed in the ruleset we ship; this
// is the safe coercion.
func metaStr(meta map[string]any, key string) string {
	v, ok := meta[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// applyMeta enriches a Pass-3 Finding with the canonical fields a YARA
// rule's `meta:` block declares. It mirrors the body of
// `opengrep.parser.parseResults` so YARA-X findings land in the CBOM
// with the same shape OpenGrep findings do — identical AssetType,
// Category, Maturity, AlgorithmPrimitive, and Library tokens. Without
// this step Pass 3 would be a second-class citizen (raw rule-id only).
//
// The canonical-token resolution for AlgorithmPrimitive reuses the
// OpenGrep canonicalizer via opengrep.CanonicalizePrimitive — same
// vocabulary, no duplication. When the rule's cbom_primitive doesn't
// canonicalize (e.g. a not-yet-standardised PQ token), the raw trimmed
// value is kept so the rule's intent isn't silently dropped.
func applyMeta(f *types.Finding, m yaraMeta) {
	if m.Description != "" {
		f.Description = m.Description
	}
	f.AssetType = mapAssetType(m.CbomAssetType)
	f.Category = mapCategory(m.Category)
	f.Maturity = mapMaturity(m.Maturity)
	f.NoiseRisk = mapNoiseRisk(m.NoiseRisk)
	f.DefaultEnabled = m.DefaultEnabled

	f.Properties.AlgorithmPrimitive = resolvePrimitive(m.CbomPrimitive)
	f.Properties.Library = m.CbomLibrary

	// Pass-3 findings default Name/RuleID to the raw YARA rule id (e.g.
	// "md5_constants"). Upgrade to a clean, consumer-facing model using the
	// rule's metadata, so binary findings are first-class CBOM components rather
	// than rule-id dumps.
	token := strings.TrimSpace(m.CbomPrimitive)
	switch f.AssetType {
	case types.AssetAlgorithm:
		if token != "" {
			f.Name = token                                 // e.g. "AES", "MD5", "SHA256"
			f.Properties.AlgorithmFamily = familyFromToken(token) // populate algorithmFamily
		}
	case types.AssetCertificate:
		f.Name = "X.509 certificate (embedded)"
	case types.AssetRelatedCryptoMaterial:
		// Embedded key material — shipping a private key in a binary is a leak.
		if strings.Contains(strings.ToLower(f.RuleID), "private") {
			f.Properties.MaterialType = "private-key"
			f.Severity = types.SeverityHigh
			name := token
			if name == "" {
				name = "Private key"
			} else {
				name += " private key"
			}
			f.Name = name
		}
	default:
		// Library detections (cbom_asset_type: library). Use the library name and
		// pull the version out of the canonical token (e.g. "OPENSSL-3.1" -> 3.1).
		if m.CbomLibrary != "" {
			f.Name = m.CbomLibrary
			if v := versionFromToken(token, m.CbomLibrary); v != "" {
				f.Properties.LibraryVersion = v
			}
		}
	}
}

// familyFromToken derives a CycloneDX-mappable algorithm family from a canonical
// Pass-3 token (e.g. "AES" -> "aes", "SHA256" -> "sha256"). The output converter
// normalizes/omits anything it doesn't recognize, so a non-family token is safe.
func familyFromToken(token string) string {
	return strings.ToLower(strings.TrimSpace(token))
}

// versionFromToken extracts a version embedded in a library token, e.g.
// "OPENSSL-3.1" / "openssl" -> "3.1". Returns "" when no version is present.
func versionFromToken(token, lib string) string {
	t := strings.TrimSpace(token)
	if t == "" {
		return ""
	}
	// Strip a leading "<LIB>-" prefix (case-insensitive) then keep a version-ish tail.
	if i := strings.IndexByte(t, '-'); i >= 0 {
		tail := t[i+1:]
		if tail != "" && (tail[0] >= '0' && tail[0] <= '9') {
			return tail
		}
	}
	return ""
}

// resolvePrimitive applies the OpenGrep canonicalizer to a raw
// cbom_primitive value. Empty input returns empty output. Inputs that
// don't canonicalize (return "") keep their raw trimmed form so the
// rule's intent isn't silently dropped — same fallback policy as
// resolveAlgorithmPrimitive in cli/internal/opengrep/parser.go.
func resolvePrimitive(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if c := opengrep.CanonicalizePrimitive(raw); c != "" {
		return c
	}
	return raw
}

// mapAssetType maps a YARA cbom_asset_type meta value to a CipherRadar
// AssetType. Mirrors mapAssetType in cli/internal/opengrep/parser.go;
// kept as a sibling here (rather than exported from opengrep) so the
// two parsers don't grow a circular dependency on each other.
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

// mapCategory maps a YARA `category` meta value to a CipherRadar
// Category. Unset / unrecognized defaults to security (conservative;
// rules covering broken algorithms should be in default scans even if
// the rule author forgot to label them).
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

// mapMaturity maps a YARA `maturity` meta value to a CipherRadar
// Maturity. Unset / unrecognized defaults to stable (forward-compat
// with rules pre-dating this field).
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

// mapNoiseRisk maps a YARA `noise_risk` meta value to a CipherRadar
// NoiseRisk. Unset / unrecognized defaults to low.
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
