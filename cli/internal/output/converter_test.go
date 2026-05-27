package output

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestConvertFinding_HardcodedSecretReroute(t *testing.T) {
	f := &types.Finding{
		ID:        "test-hc-1",
		Name:      "hardcoded API key",
		AssetType: types.AssetAlgorithm, // scanner currently emits this
		Properties: types.CryptoProperties{
			AlgorithmPrimitive: "HARDCODED-SECRET",
		},
	}
	comp := convertFinding(f)

	if comp.CryptoProperties == nil {
		t.Fatal("CryptoProperties is nil")
	}
	if comp.CryptoProperties.AssetType != "related-crypto-material" {
		t.Errorf("AssetType = %q, want related-crypto-material (rerouted)",
			comp.CryptoProperties.AssetType)
	}
	if comp.CryptoProperties.AlgorithmProperties != nil {
		t.Error("AlgorithmProperties should be nil after reroute")
	}
	if comp.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		t.Fatal("RelatedCryptoMaterialProperties is nil")
	}
	if comp.CryptoProperties.RelatedCryptoMaterialProperties.Type != cyclonedx17.RelatedCryptoMaterialTypeOther {
		t.Errorf("MaterialType = %q, want other",
			comp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	}
}

func TestConvertAlgorithmProperties_KnownCanonicalToken(t *testing.T) {
	// AlgorithmPrimitive set to a canonical algorithm token should derive the
	// correct primitive (hash for MD5, block-cipher for AES) — not pass through
	// the raw token.
	for _, tc := range []struct {
		name     string
		token    string
		wantPrim cyclonedx17.Primitive
	}{
		{"MD5 → hash", "MD5", cyclonedx17.PrimitiveHash},
		{"AES-256-GCM → block-cipher", "AES-256-GCM", cyclonedx17.PrimitiveBlockCipher},
		{"unknown → other", "WAT-1234", cyclonedx17.PrimitiveOther},
		// Regression: all-caps tokens emitted by scanner rules must not fall through to PrimitiveOther.
		{"BCRYPT → kdf", "BCRYPT", cyclonedx17.PrimitiveKDF},
		{"SCRYPT → kdf", "SCRYPT", cyclonedx17.PrimitiveKDF},
		{"BLOWFISH → block-cipher", "BLOWFISH", cyclonedx17.PrimitiveBlockCipher},
		{"TWOFISH → block-cipher", "TWOFISH", cyclonedx17.PrimitiveBlockCipher},
		{"WHIRLPOOL → hash", "WHIRLPOOL", cyclonedx17.PrimitiveHash},
		{"POLY1305 → mac", "POLY1305", cyclonedx17.PrimitiveMAC},
		{"CHACHA20 → stream-cipher", "CHACHA20", cyclonedx17.PrimitiveStreamCipher},
		{"EDDSA → signature", "EDDSA", cyclonedx17.PrimitiveSignature},
		// Newly added tokens (Fix 4).
		{"KECCAK → hash", "KECCAK", cyclonedx17.PrimitiveHash},
		{"AES-KW → key-wrap", "AES-KW", cyclonedx17.PrimitiveKeyWrap},
		{"CURVE25519 → key-agree", "CURVE25519", cyclonedx17.PrimitiveKeyAgree},
		{"DILITHIUM → signature", "DILITHIUM", cyclonedx17.PrimitiveSignature},
		{"FN-DSA → signature", "FN-DSA", cyclonedx17.PrimitiveSignature},
		{"ARGON2ID → kdf", "ARGON2ID", cyclonedx17.PrimitiveKDF},
		{"GMAC → mac", "GMAC", cyclonedx17.PrimitiveMAC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap := convertAlgorithmProperties(&types.CryptoProperties{
				AlgorithmPrimitive: tc.token,
			})
			if ap.Primitive != tc.wantPrim {
				t.Errorf("Primitive = %q, want %q", ap.Primitive, tc.wantPrim)
			}
		})
	}
}

func TestConvertFinding_RerouteMarkers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		token         string
		wantAssetType string
		wantMaterial  cyclonedx17.RelatedCryptoMaterialType
	}{
		{"hardcoded secret", "HARDCODED-SECRET", "related-crypto-material", cyclonedx17.RelatedCryptoMaterialTypeOther},
		{"private key PEM", "PRIVATE-KEY-PEM", "related-crypto-material", cyclonedx17.RelatedCryptoMaterialTypePrivateKey},
		{"public key PEM", "PUBLIC-KEY-PEM", "related-crypto-material", cyclonedx17.RelatedCryptoMaterialTypePublicKey},
		{"initialization vector", "INITIALIZATION-VECTOR", "related-crypto-material", cyclonedx17.RelatedCryptoMaterialTypeInitializationVector},
		// CycloneDX 1.7 uses "secret-key" (not "symmetric-key"); SYMMETRIC-KEY normalizes to secret-key.
		{"symmetric key", "SYMMETRIC-KEY", "related-crypto-material", cyclonedx17.RelatedCryptoMaterialTypeSecretKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &types.Finding{
				ID:        "t",
				Name:      tc.name,
				AssetType: types.AssetAlgorithm,
				Properties: types.CryptoProperties{
					AlgorithmPrimitive: tc.token,
				},
			}
			comp := convertFinding(f)
			if comp.CryptoProperties.AssetType != tc.wantAssetType {
				t.Errorf("AssetType = %q, want %q", comp.CryptoProperties.AssetType, tc.wantAssetType)
			}
			if comp.CryptoProperties.RelatedCryptoMaterialProperties == nil {
				t.Fatal("RelatedCryptoMaterialProperties is nil")
			}
			if comp.CryptoProperties.RelatedCryptoMaterialProperties.Type != tc.wantMaterial {
				t.Errorf("MaterialType = %q, want %q",
					comp.CryptoProperties.RelatedCryptoMaterialProperties.Type, tc.wantMaterial)
			}
		})
	}
}

func TestConvertFinding_ProtocolReroute(t *testing.T) {
	for _, token := range []string{"TLS", "TLS-1.2", "SSH", "IKEV2"} {
		t.Run(token, func(t *testing.T) {
			f := &types.Finding{
				ID:        "t",
				Name:      token,
				AssetType: types.AssetAlgorithm,
				Properties: types.CryptoProperties{
					AlgorithmPrimitive: token,
				},
			}
			comp := convertFinding(f)
			if comp.CryptoProperties.AssetType != "protocol" {
				t.Errorf("AssetType = %q, want protocol", comp.CryptoProperties.AssetType)
			}
			if comp.CryptoProperties.AlgorithmProperties != nil {
				t.Error("AlgorithmProperties should be nil after protocol reroute")
			}
		})
	}
}

func TestConvertFinding_CertificateReroute(t *testing.T) {
	for _, token := range []string{"CERTIFICATE", "CERTIFICATE-X509", "X509"} {
		t.Run(token, func(t *testing.T) {
			f := &types.Finding{
				ID:        "t",
				Name:      token,
				AssetType: types.AssetAlgorithm,
				Properties: types.CryptoProperties{
					AlgorithmPrimitive: token,
				},
			}
			comp := convertFinding(f)
			if comp.CryptoProperties.AssetType != "certificate" {
				t.Errorf("AssetType = %q, want certificate", comp.CryptoProperties.AssetType)
			}
			if comp.CryptoProperties.CertificateProperties == nil {
				t.Error("CertificateProperties should not be nil after certificate reroute")
			}
		})
	}
}

func TestConvertFinding_LibraryAssetType_EmitsLibraryComponent(t *testing.T) {
	f := &types.Finding{
		ID:        "test-lib-1",
		Name:      "openssl",
		AssetType: types.AssetType("library"), // bug source: opengrep cbom-library-import rule
		Properties: types.CryptoProperties{
			AlgorithmPrimitive: "CRYPTO-LIBRARY-IMPORT",
		},
		Location: types.Location{File: "requirements.txt", StartLine: 4},
	}
	var tally validationTally
	comp := convertFindingTally(f, &tally)

	if comp.Type != "library" {
		t.Errorf("Type = %q, want library (per ADR-040)", comp.Type)
	}
	if comp.CryptoProperties != nil {
		t.Errorf("CryptoProperties should be nil for library components, got %+v", comp.CryptoProperties)
	}
	if comp.Name != "openssl" {
		t.Errorf("Name = %q, want openssl", comp.Name)
	}
	// Library findings do NOT count as a validation violation — they take a
	// designed path, not a fall-through.
	if tally.Total != 0 {
		t.Errorf("Total = %d, want 0 (library is designed path, not violation)", tally.Total)
	}
}

func TestConvertScanResult_TallyAccumulates(t *testing.T) {
	result := &types.ScanResult{
		Target: "/tmp/x",
		Findings: []types.Finding{
			{ID: "1", AssetType: types.AssetAlgorithm, Properties: types.CryptoProperties{AlgorithmPrimitive: "HARDCODED-SECRET"}},
			{ID: "2", AssetType: types.AssetType("library"), Name: "openssl"},
			{ID: "3", AssetType: types.AssetType("WAT")}, // unknown assetType → violation
		},
	}
	_, tally := ConvertScanResultWithTally(result)
	// HARDCODED-SECRET reroutes cleanly (no violation), library uses designed
	// path (no violation), WAT is the only true unknown.
	if tally.Total != 1 {
		t.Errorf("Total = %d, want 1 (only WAT assetType is unknown)", tally.Total)
	}
	if tally.AssetTypes != 1 {
		t.Errorf("AssetTypes = %d, want 1", tally.AssetTypes)
	}
}

func TestConverter_QuantumNotApplicable_OmitsProperty(t *testing.T) {
	f := &types.Finding{
		ID: "1", Name: "openssl", AssetType: types.AssetType("library"),
		Properties: types.CryptoProperties{QuantumStatus: types.QuantumNotApplicable},
	}
	comp := convertFinding(f)
	for _, p := range comp.Properties {
		if p.Name == "quantumStatus" {
			t.Errorf("property quantumStatus should be omitted for not-applicable; got value=%q", p.Value)
		}
	}
}
