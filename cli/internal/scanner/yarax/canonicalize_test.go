package yarax

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestParseMeta_HappyPath(t *testing.T) {
	raw := map[string]any{
		"description":      " OpenSSL 3.0 ",
		"cbom_primitive":   "OPENSSL-3.0",
		"cbom_asset_type":  "library",
		"cbom_library":     "openssl",
		"category":         "inventory",
		"maturity":         "stable",
		"noise_risk":       "low",
		"default_enabled":  "true",
	}
	m := parseMeta(raw)

	if m.Description != "OpenSSL 3.0" {
		t.Errorf("Description trimmed mismatch: %q", m.Description)
	}
	if m.CbomPrimitive != "OPENSSL-3.0" {
		t.Errorf("CbomPrimitive: %q", m.CbomPrimitive)
	}
	if m.CbomAssetType != "library" {
		t.Errorf("CbomAssetType: %q", m.CbomAssetType)
	}
	if m.CbomLibrary != "openssl" {
		t.Errorf("CbomLibrary: %q", m.CbomLibrary)
	}
	if m.Category != "inventory" {
		t.Errorf("Category: %q", m.Category)
	}
	if m.Maturity != "stable" {
		t.Errorf("Maturity: %q", m.Maturity)
	}
	if m.NoiseRisk != "low" {
		t.Errorf("NoiseRisk: %q", m.NoiseRisk)
	}
	if !m.DefaultEnabled {
		t.Errorf("DefaultEnabled expected true")
	}
}

func TestParseMeta_DefaultEnabledFalseString(t *testing.T) {
	m := parseMeta(map[string]any{"default_enabled": "false"})
	if m.DefaultEnabled {
		t.Errorf("expected DefaultEnabled=false for \"false\" string")
	}
}

func TestParseMeta_DefaultEnabledBool(t *testing.T) {
	mTrue := parseMeta(map[string]any{"default_enabled": true})
	mFalse := parseMeta(map[string]any{"default_enabled": false})
	if !mTrue.DefaultEnabled {
		t.Errorf("expected DefaultEnabled=true for bool true")
	}
	if mFalse.DefaultEnabled {
		t.Errorf("expected DefaultEnabled=false for bool false")
	}
}

func TestParseMeta_MissingKeysSafeDefault(t *testing.T) {
	m := parseMeta(nil)
	if !m.DefaultEnabled {
		t.Errorf("nil meta should default DefaultEnabled=true (forward-compat)")
	}
	if m.CbomPrimitive != "" || m.CbomAssetType != "" {
		t.Errorf("nil meta should leave string fields empty")
	}
}

func TestApplyMeta_PopulatesCanonicalFields(t *testing.T) {
	f := types.Finding{RuleID: "openssl_version_3_0", Description: "raw"}
	applyMeta(&f, yaraMeta{
		Description:    "OpenSSL 3.0 banner",
		CbomPrimitive:  "openssl-3.0", // exercise canonicalizer
		CbomAssetType:  "library",
		CbomLibrary:    "openssl",
		Category:       "inventory",
		Maturity:       "stable",
		NoiseRisk:      "low",
		DefaultEnabled: true,
	})

	if f.Description != "OpenSSL 3.0 banner" {
		t.Errorf("Description not overridden by meta: %q", f.Description)
	}
	// AssetType "library" isn't in the strict allow-list; mapAssetType
	// preserves it as-is via the default branch.
	if string(f.AssetType) != "library" {
		t.Errorf("AssetType expected library, got %q", f.AssetType)
	}
	if f.Category != types.CategoryInventory {
		t.Errorf("Category: %q", f.Category)
	}
	if f.Maturity != types.MaturityStable {
		t.Errorf("Maturity: %q", f.Maturity)
	}
	if f.Properties.AlgorithmPrimitive != "OPENSSL-3.0" {
		t.Errorf("AlgorithmPrimitive expected canonicalized OPENSSL-3.0, got %q",
			f.Properties.AlgorithmPrimitive)
	}
	if f.Properties.Library != "openssl" {
		t.Errorf("Library: %q", f.Properties.Library)
	}
	if !f.DefaultEnabled {
		t.Errorf("DefaultEnabled should propagate")
	}
}

func TestApplyMeta_NonCanonicalizablePrimitivePreserved(t *testing.T) {
	// resolvePrimitive falls back to the raw trimmed value when the
	// canonicalizer rejects the input — matches the OpenGrep parser's
	// "don't silently drop rule intent" policy.
	f := types.Finding{}
	applyMeta(&f, yaraMeta{CbomPrimitive: "  WEIRD-PQ-NAME  "})
	if f.Properties.AlgorithmPrimitive != "WEIRD-PQ-NAME" {
		t.Errorf("expected raw trimmed token preserved, got %q", f.Properties.AlgorithmPrimitive)
	}
}

func TestApplyMeta_EmptyMetaPicksSafeDefaults(t *testing.T) {
	f := types.Finding{}
	applyMeta(&f, yaraMeta{DefaultEnabled: true})

	if f.AssetType != types.AssetAlgorithm {
		t.Errorf("empty asset_type should default to algorithm, got %q", f.AssetType)
	}
	if f.Category != types.CategorySecurity {
		t.Errorf("empty category should default to security, got %q", f.Category)
	}
	if f.Maturity != types.MaturityStable {
		t.Errorf("empty maturity should default to stable, got %q", f.Maturity)
	}
	if f.NoiseRisk != types.NoiseRiskLow {
		t.Errorf("empty noise_risk should default to low, got %q", f.NoiseRisk)
	}
}

func TestMapAssetType_KnownVariants(t *testing.T) {
	cases := map[string]types.AssetType{
		"algorithm":               types.AssetAlgorithm,
		"protocol":                types.AssetProtocol,
		"certificate":             types.AssetCertificate,
		"related-crypto-material": types.AssetRelatedCryptoMaterial,
	}
	for in, want := range cases {
		if got := mapAssetType(in); got != want {
			t.Errorf("mapAssetType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolvePrimitive_CanonicalizerWiredThrough(t *testing.T) {
	// Exercise a value that the opengrep canonicalizer normalises so we
	// verify the wrapper is calling it (not skipping the canonicalizer
	// and returning the raw value).
	if got := resolvePrimitive("sha256"); got != "SHA-256" {
		t.Errorf("expected canonicalized SHA-256, got %q", got)
	}
	if got := resolvePrimitive(""); got != "" {
		t.Errorf("empty input should round-trip empty, got %q", got)
	}
}

func TestApplyMeta_Pass3Quality(t *testing.T) {
	// Algorithm: clean name + family from the canonical token.
	alg := &types.Finding{RuleID: "md5_constants", Name: "md5_constants"}
	applyMeta(alg, yaraMeta{CbomPrimitive: "MD5", CbomAssetType: "algorithm", DefaultEnabled: true})
	if alg.Name != "MD5" || alg.Properties.AlgorithmFamily != "md5" {
		t.Errorf("algorithm: name=%q family=%q, want MD5/md5", alg.Name, alg.Properties.AlgorithmFamily)
	}

	// Embedded private key: typed private-key + raised severity + clean name.
	key := &types.Finding{RuleID: "embedded_pem_rsa_private", Name: "embedded_pem_rsa_private"}
	applyMeta(key, yaraMeta{CbomPrimitive: "RSA", CbomAssetType: "related-crypto-material", DefaultEnabled: true})
	if key.Properties.MaterialType != "private-key" || key.Severity != types.SeverityHigh {
		t.Errorf("key: matType=%q sev=%q, want private-key/high", key.Properties.MaterialType, key.Severity)
	}
	if key.Name != "RSA private key" {
		t.Errorf("key name = %q, want 'RSA private key'", key.Name)
	}

	// Library: clean name + version extracted from the token (no source purl here).
	lib := &types.Finding{RuleID: "openssl_version_3_1", Name: "openssl_version_3_1"}
	applyMeta(lib, yaraMeta{CbomPrimitive: "OPENSSL-3.1", CbomAssetType: "library", CbomLibrary: "openssl", DefaultEnabled: true})
	if lib.Name != "openssl" || lib.Properties.LibraryVersion != "3.1" {
		t.Errorf("lib: name=%q version=%q, want openssl/3.1", lib.Name, lib.Properties.LibraryVersion)
	}
}
