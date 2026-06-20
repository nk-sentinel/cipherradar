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

func propValue(comp Component, name string) (string, bool) {
	for _, p := range comp.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func TestConvertFinding_LibraryIdentity(t *testing.T) {
	// A library finding enriched with a resolved package emits purl/version/group
	// and upgrades the display name to the concrete package.
	lib := convertFinding(&types.Finding{
		ID: "1", Name: "node-forge", AssetType: types.AssetType("library"),
		Properties: types.CryptoProperties{
			Library: "node-forge", LibraryVersion: "1.3.1",
			LibraryPurl: "pkg:npm/node-forge@1.3.1",
		},
	})
	if lib.Version != "1.3.1" || lib.Purl != "pkg:npm/node-forge@1.3.1" {
		t.Errorf("library component identity = version %q purl %q", lib.Version, lib.Purl)
	}
	if v, ok := propValue(lib, "library"); !ok || v != "node-forge" {
		t.Errorf("library property = %q (ok=%v)", v, ok)
	}

	// A crypto-asset finding (e.g. PHP mcrypt) with a maven library hint gets the
	// purl/group without losing cryptoProperties.
	maven := convertFinding(&types.Finding{
		ID: "2", Name: "RSA", AssetType: types.AssetAlgorithm,
		Properties: types.CryptoProperties{
			AlgorithmFamily: "rsa", Library: "bouncycastle",
			LibraryGroup: "org.bouncycastle", LibraryVersion: "1.77",
			LibraryPurl: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77",
		},
	})
	if maven.Group != "org.bouncycastle" || maven.Purl == "" {
		t.Errorf("crypto-asset library identity = group %q purl %q", maven.Group, maven.Purl)
	}
	if maven.CryptoProperties == nil {
		t.Error("crypto-asset must retain cryptoProperties when carrying a library purl")
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

func certFinding(id, subject, pubAlgo string, keySize int) types.Finding {
	return types.Finding{
		ID: id, AssetType: types.AssetCertificate,
		Name: "X.509 Certificate (" + subject + ")",
		Properties: types.CryptoProperties{
			AlgorithmPrimitive:        "CERTIFICATE-X509",
			SubjectName:               "CN=" + subject,
			SignatureAlgorithm:        "SHA256-RSA",
			CertificateFormat:         "X.509",
			SubjectPublicKeyAlgorithm: pubAlgo,
			SubjectPublicKeySize:      keySize,
			CertificateExtensions:     []string{"KeyUsage=digitalSignature", "BasicConstraints=CA:false"},
		},
	}
}

func findComp(bom *BOM, ref string) (Component, bool) {
	for _, c := range bom.Components {
		if c.BOMRef == ref {
			return c, true
		}
	}
	return Component{}, false
}

func TestConverter_CertificateLinkedGraph(t *testing.T) {
	result := &types.ScanResult{Target: "/tmp/x", Findings: []types.Finding{
		certFinding("c1", "a.example.com", "RSA", 2048),
		certFinding("c2", "b.example.com", "RSA", 2048), // shares SHA256-RSA + RSA-2048
	}}
	bom, _ := ConvertScanResultWithTally(result)

	c1, ok := findComp(bom, "c1")
	if !ok || c1.CryptoProperties.CertificateProperties == nil {
		t.Fatal("cert c1 missing")
	}
	cp := c1.CryptoProperties.CertificateProperties
	if cp.SignatureAlgorithmRef == "" || cp.SubjectPublicKeyRef == "" {
		t.Errorf("cert refs not wired: sig=%q key=%q", cp.SignatureAlgorithmRef, cp.SubjectPublicKeyRef)
	}
	if cp.CertificateExtension == "" {
		t.Error("certificateExtension should be populated")
	}
	// Shared signature-algorithm component exists exactly once.
	sigCount := 0
	for _, c := range bom.Components {
		if c.BOMRef == cp.SignatureAlgorithmRef {
			sigCount++
		}
	}
	if sigCount != 1 {
		t.Errorf("expected exactly 1 shared sig-algo component, got %d", sigCount)
	}
	// Per-cert public-key material component exists and references the pubkey algo.
	keyComp, ok := findComp(bom, cp.SubjectPublicKeyRef)
	if !ok || keyComp.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		t.Fatal("subject public-key component missing")
	}
	if keyComp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef == "" {
		t.Error("public-key component should reference the pubkey-algorithm component")
	}
	if keyComp.CryptoProperties.RelatedCryptoMaterialProperties.Size != 2048 {
		t.Errorf("public-key size = %d, want 2048", keyComp.CryptoProperties.RelatedCryptoMaterialProperties.Size)
	}
	// Dependency edges recorded for the cert.
	var certDep *Dependency
	for i := range bom.Dependencies {
		if bom.Dependencies[i].Ref == "c1" {
			certDep = &bom.Dependencies[i]
		}
	}
	if certDep == nil || len(certDep.DependsOn) < 2 {
		t.Errorf("cert c1 should depend on sig-algo + public-key, got %+v", certDep)
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

func propValue(comp Component, name string) (string, bool) {
	for _, p := range comp.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func TestConverter_QuantumMigrationProps(t *testing.T) {
	// Quantum-vulnerable RSA public-key encryption → critical (HNDL) + targets.
	rsa := convertFinding(&types.Finding{
		ID: "1", Name: "RSA", AssetType: types.AssetAlgorithm,
		Properties: types.CryptoProperties{
			AlgorithmFamily: "rsa", Primitive: "pke",
			QuantumStatus: types.QuantumVulnerable, KeySize: 2048,
		},
	})
	if v, ok := propValue(rsa, "cradar:quantum:priority"); !ok || v != "critical" {
		t.Errorf("RSA priority = %q (ok=%v), want critical", v, ok)
	}
	if _, ok := propValue(rsa, "cradar:quantum:recommendation"); !ok {
		t.Error("RSA recommendation property missing")
	}
	if _, ok := propValue(rsa, "cradar:quantum:migrationTarget"); !ok {
		t.Error("RSA migrationTarget property missing")
	}

	// Quantum-safe ML-KEM → priority none.
	mlkem := convertFinding(&types.Finding{
		ID: "2", Name: "ML-KEM", AssetType: types.AssetAlgorithm,
		Properties: types.CryptoProperties{
			AlgorithmFamily: "ml-kem", Primitive: "kem", QuantumStatus: types.QuantumSafe,
		},
	})
	if v, ok := propValue(mlkem, "cradar:quantum:priority"); !ok || v != "none" {
		t.Errorf("ML-KEM priority = %q (ok=%v), want none", v, ok)
	}

	// Not-applicable → no migration props at all.
	lib := convertFinding(&types.Finding{
		ID: "3", Name: "openssl", AssetType: types.AssetType("library"),
		Properties: types.CryptoProperties{QuantumStatus: types.QuantumNotApplicable},
	})
	if _, ok := propValue(lib, "cradar:quantum:priority"); ok {
		t.Error("not-applicable finding should have no quantum priority property")
	}
}

func TestDeriveParameterSet(t *testing.T) {
	cases := []struct {
		prim, family string
		keySize      int
		want         string
	}{
		{"ML-KEM-768", "ml-kem", 0, "768"},
		{"AES-256-GCM", "aes", 0, "256"},
		{"", "rsa", 2048, "2048"},
		{"", "ec", 256, "256"},
		{"", "", 0, ""},
	}
	for _, tc := range cases {
		p := &types.CryptoProperties{AlgorithmPrimitive: tc.prim, AlgorithmFamily: tc.family, KeySize: tc.keySize}
		got := deriveParameterSet(p)
		if got != tc.want {
			t.Errorf("deriveParameterSet(prim=%q fam=%q ks=%d) = %q, want %q", tc.prim, tc.family, tc.keySize, got, tc.want)
		}
	}
}
