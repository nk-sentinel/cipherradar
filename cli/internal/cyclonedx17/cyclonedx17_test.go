package cyclonedx17

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAlgorithmPropertiesAllFields(t *testing.T) {
	ap := AlgorithmProperties{
		Primitive:              PrimitiveBlockCipher,
		AlgorithmFamily:        AlgorithmFamilyAES,
		ParameterSetIdentifier: "256",
		ExecutionEnvironment:   "software",
		ImplementationPlatform: "x86_64",
		CertificationLevels:    []string{"FIPS 140-3 Level 1"},
		Mode:                   ModeGCM,
		Padding:                PaddingPKCS7,
		CryptoFunctions:        []CryptoFunction{CryptoFunctionEncrypt, CryptoFunctionDecrypt},
		ClassicalSecurityLevel:   256,
		NistQuantumSecurityLevel: 1,
	}

	if ap.Primitive != PrimitiveBlockCipher {
		t.Errorf("expected primitive %q, got %q", PrimitiveBlockCipher, ap.Primitive)
	}
	if ap.AlgorithmFamily != AlgorithmFamilyAES {
		t.Errorf("expected algorithm family %q, got %q", AlgorithmFamilyAES, ap.AlgorithmFamily)
	}
	if ap.ParameterSetIdentifier != "256" {
		t.Errorf("expected parameter set identifier %q, got %q", "256", ap.ParameterSetIdentifier)
	}
	if ap.ExecutionEnvironment != "software" {
		t.Errorf("expected execution environment %q, got %q", "software", ap.ExecutionEnvironment)
	}
	if ap.ImplementationPlatform != "x86_64" {
		t.Errorf("expected implementation platform %q, got %q", "x86_64", ap.ImplementationPlatform)
	}
	if len(ap.CertificationLevels) != 1 || ap.CertificationLevels[0] != "FIPS 140-3 Level 1" {
		t.Errorf("unexpected certification levels: %v", ap.CertificationLevels)
	}
	if ap.Mode != ModeGCM {
		t.Errorf("expected mode %q, got %q", ModeGCM, ap.Mode)
	}
	if ap.Padding != PaddingPKCS7 {
		t.Errorf("expected padding %q, got %q", PaddingPKCS7, ap.Padding)
	}
	if len(ap.CryptoFunctions) != 2 {
		t.Errorf("expected 2 crypto functions, got %d", len(ap.CryptoFunctions))
	}
	if ap.ClassicalSecurityLevel != 256 {
		t.Errorf("expected classical security level 256, got %d", ap.ClassicalSecurityLevel)
	}
	if ap.NistQuantumSecurityLevel != 1 {
		t.Errorf("expected NIST quantum security level 1, got %d", ap.NistQuantumSecurityLevel)
	}
}

func TestCertificatePropertiesAllFields(t *testing.T) {
	cp := CertificateProperties{
		SubjectName:           "CN=example.com",
		IssuerName:            "CN=Let's Encrypt Authority X3",
		NotValidBefore:        "2025-01-01T00:00:00Z",
		NotValidAfter:         "2026-01-01T00:00:00Z",
		SignatureAlgorithmRef: "alg-sha256-rsa",
		SubjectPublicKeyRef:   "key-rsa-2048",
		CertificateFormat:     "X.509",
		CertificateExtension:  "crt",
	}

	if cp.SubjectName != "CN=example.com" {
		t.Errorf("expected subject name %q, got %q", "CN=example.com", cp.SubjectName)
	}
	if cp.IssuerName != "CN=Let's Encrypt Authority X3" {
		t.Errorf("expected issuer name %q, got %q", "CN=Let's Encrypt Authority X3", cp.IssuerName)
	}
	if cp.NotValidBefore != "2025-01-01T00:00:00Z" {
		t.Errorf("expected not valid before %q, got %q", "2025-01-01T00:00:00Z", cp.NotValidBefore)
	}
	if cp.NotValidAfter != "2026-01-01T00:00:00Z" {
		t.Errorf("expected not valid after %q, got %q", "2026-01-01T00:00:00Z", cp.NotValidAfter)
	}
	if cp.SignatureAlgorithmRef != "alg-sha256-rsa" {
		t.Errorf("expected signature algorithm ref %q, got %q", "alg-sha256-rsa", cp.SignatureAlgorithmRef)
	}
	if cp.SubjectPublicKeyRef != "key-rsa-2048" {
		t.Errorf("expected subject public key ref %q, got %q", "key-rsa-2048", cp.SubjectPublicKeyRef)
	}
	if cp.CertificateFormat != "X.509" {
		t.Errorf("expected certificate format %q, got %q", "X.509", cp.CertificateFormat)
	}
	if cp.CertificateExtension != "crt" {
		t.Errorf("expected certificate extension %q, got %q", "crt", cp.CertificateExtension)
	}
}

func TestProtocolPropertiesWithCipherSuites(t *testing.T) {
	pp := ProtocolProperties{
		Type:    "tls",
		Version: "1.3",
		CipherSuites: []CipherSuite{
			{
				Name:        "TLS_AES_256_GCM_SHA384",
				Algorithms:  []string{"aes-256-gcm", "sha-384"},
				Identifiers: []string{"0x13,0x02"},
			},
			{
				Name:        "TLS_CHACHA20_POLY1305_SHA256",
				Algorithms:  []string{"chacha20-poly1305", "sha-256"},
				Identifiers: []string{"0x13,0x03"},
			},
		},
		IKEv2TransformTypes: []IKEv2Transform{
			{
				Type:       "encryption",
				Algorithms: []string{"aes-256-gcm"},
			},
		},
		CryptoRefArray: []string{"ref-aes-256", "ref-sha-384"},
	}

	if pp.Type != "tls" {
		t.Errorf("expected type %q, got %q", "tls", pp.Type)
	}
	if pp.Version != "1.3" {
		t.Errorf("expected version %q, got %q", "1.3", pp.Version)
	}
	if len(pp.CipherSuites) != 2 {
		t.Fatalf("expected 2 cipher suites, got %d", len(pp.CipherSuites))
	}
	if pp.CipherSuites[0].Name != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("expected cipher suite name %q, got %q", "TLS_AES_256_GCM_SHA384", pp.CipherSuites[0].Name)
	}
	if len(pp.CipherSuites[0].Algorithms) != 2 {
		t.Errorf("expected 2 algorithms in first cipher suite, got %d", len(pp.CipherSuites[0].Algorithms))
	}
	if len(pp.IKEv2TransformTypes) != 1 {
		t.Fatalf("expected 1 IKEv2 transform type, got %d", len(pp.IKEv2TransformTypes))
	}
	if pp.IKEv2TransformTypes[0].Type != "encryption" {
		t.Errorf("expected IKEv2 transform type %q, got %q", "encryption", pp.IKEv2TransformTypes[0].Type)
	}
	if len(pp.CryptoRefArray) != 2 {
		t.Errorf("expected 2 crypto refs, got %d", len(pp.CryptoRefArray))
	}
}

func TestRelatedCryptoMaterialPropertiesWithSecuredBy(t *testing.T) {
	rcm := RelatedCryptoMaterialProperties{
		Type:         RelatedCryptoMaterialTypePrivateKey,
		ID:           "key-001",
		State:        RelatedCryptoMaterialStateActive,
		AlgorithmRef: "alg-rsa-2048",
		SecuredBy: &SecuredBy{
			Mechanism:    "software",
			AlgorithmRef: "alg-aes-256",
		},
		Size: 2048,
	}

	if rcm.Type != RelatedCryptoMaterialTypePrivateKey {
		t.Errorf("expected type %q, got %q", RelatedCryptoMaterialTypePrivateKey, rcm.Type)
	}
	if rcm.ID != "key-001" {
		t.Errorf("expected ID %q, got %q", "key-001", rcm.ID)
	}
	if rcm.State != RelatedCryptoMaterialStateActive {
		t.Errorf("expected state %q, got %q", RelatedCryptoMaterialStateActive, rcm.State)
	}
	if rcm.AlgorithmRef != "alg-rsa-2048" {
		t.Errorf("expected algorithm ref %q, got %q", "alg-rsa-2048", rcm.AlgorithmRef)
	}
	if rcm.SecuredBy == nil {
		t.Fatal("expected SecuredBy to be non-nil")
	}
	if rcm.SecuredBy.Mechanism != "software" {
		t.Errorf("expected mechanism %q, got %q", "software", rcm.SecuredBy.Mechanism)
	}
	if rcm.SecuredBy.AlgorithmRef != "alg-aes-256" {
		t.Errorf("expected secured by algorithm ref %q, got %q", "alg-aes-256", rcm.SecuredBy.AlgorithmRef)
	}
	if rcm.Size != 2048 {
		t.Errorf("expected size 2048, got %d", rcm.Size)
	}
}

func TestCryptoPropertiesJSONRoundTrip(t *testing.T) {
	original := CryptoProperties{
		AssetType: "algorithm",
		AlgorithmProperties: &AlgorithmProperties{
			Primitive:                PrimitiveBlockCipher,
			AlgorithmFamily:         AlgorithmFamilyAES,
			ParameterSetIdentifier:  "256",
			ExecutionEnvironment:    "software",
			ImplementationPlatform:  "x86_64",
			CertificationLevels:     []string{"FIPS 140-3 Level 1"},
			Mode:                    ModeGCM,
			Padding:                 PaddingPKCS7,
			CryptoFunctions:         []CryptoFunction{CryptoFunctionEncrypt, CryptoFunctionDecrypt},
			ClassicalSecurityLevel:   256,
			NistQuantumSecurityLevel: 1,
		},
		OID: "2.16.840.1.101.3.4.1.46",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal CryptoProperties: %v", err)
	}

	var restored CryptoProperties
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal CryptoProperties: %v", err)
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("round-trip mismatch:\noriginal: %+v\nrestored: %+v", original, restored)
	}
}

func TestCryptoPropertiesJSONRoundTripCertificate(t *testing.T) {
	original := CryptoProperties{
		AssetType: "certificate",
		CertificateProperties: &CertificateProperties{
			SubjectName:           "CN=example.com",
			IssuerName:            "CN=CA",
			NotValidBefore:        "2025-01-01T00:00:00Z",
			NotValidAfter:         "2026-01-01T00:00:00Z",
			SignatureAlgorithmRef: "alg-sha256-rsa",
			SubjectPublicKeyRef:   "key-rsa-2048",
			CertificateFormat:     "X.509",
			CertificateExtension:  "crt",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored CryptoProperties
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("round-trip mismatch:\noriginal: %+v\nrestored: %+v", original, restored)
	}
}

func TestCryptoPropertiesJSONRoundTripProtocol(t *testing.T) {
	original := CryptoProperties{
		AssetType: "protocol",
		ProtocolProperties: &ProtocolProperties{
			Type:    "tls",
			Version: "1.3",
			CipherSuites: []CipherSuite{
				{
					Name:        "TLS_AES_256_GCM_SHA384",
					Algorithms:  []string{"aes-256-gcm"},
					Identifiers: []string{"0x13,0x02"},
				},
			},
			CryptoRefArray: []string{"ref-1"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored CryptoProperties
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("round-trip mismatch:\noriginal: %+v\nrestored: %+v", original, restored)
	}
}

func TestCryptoPropertiesJSONRoundTripRelatedCryptoMaterial(t *testing.T) {
	original := CryptoProperties{
		AssetType: "related-crypto-material",
		RelatedCryptoMaterialProperties: &RelatedCryptoMaterialProperties{
			Type:         RelatedCryptoMaterialTypePrivateKey,
			ID:           "key-001",
			State:        RelatedCryptoMaterialStateActive,
			AlgorithmRef: "alg-rsa-2048",
			SecuredBy: &SecuredBy{
				Mechanism:    "hsm",
				AlgorithmRef: "alg-aes-256",
			},
			Size: 2048,
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored CryptoProperties
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("round-trip mismatch:\noriginal: %+v\nrestored: %+v", original, restored)
	}
}

func TestEnumConstantValues(t *testing.T) {
	// Primitive enum values
	primitives := map[Primitive]string{
		PrimitiveDRBG:         "drbg",
		PrimitiveBlockCipher:  "block-cipher",
		PrimitiveStreamCipher: "stream-cipher",
		PrimitiveHash:         "hash",
		PrimitiveMAC:          "mac",
		PrimitiveSignature:    "signature",
		PrimitiveKDF:          "kdf",
		PrimitiveKeyAgree:     "key-agree",
		PrimitivePKE:          "pke",
		PrimitiveXOF:          "xof",
		PrimitiveAE:           "ae",
		PrimitiveOther:        "other",
		PrimitiveUnknown:      "unknown",
	}
	for p, expected := range primitives {
		if string(p) != expected {
			t.Errorf("Primitive: expected %q, got %q", expected, string(p))
		}
	}

	// Mode enum values
	modes := map[Mode]string{
		ModeCBC:     "cbc",
		ModeECB:     "ecb",
		ModeCTR:     "ctr",
		ModeGCM:     "gcm",
		ModeCCM:     "ccm",
		ModeOFB:     "ofb",
		ModeCFB:     "cfb",
		ModeOther:   "other",
		ModeUnknown: "unknown",
	}
	for m, expected := range modes {
		if string(m) != expected {
			t.Errorf("Mode: expected %q, got %q", expected, string(m))
		}
	}

	// Padding enum values
	paddings := map[Padding]string{
		PaddingPKCS5:   "pkcs5",
		PaddingPKCS7:   "pkcs7",
		PaddingOAEP:    "oaep",
		PaddingRaw:     "raw",
		PaddingOther:   "other",
		PaddingUnknown: "unknown",
	}
	for p, expected := range paddings {
		if string(p) != expected {
			t.Errorf("Padding: expected %q, got %q", expected, string(p))
		}
	}

	// CryptoFunction enum values
	functions := map[CryptoFunction]string{
		CryptoFunctionGenerate:    "generate",
		CryptoFunctionKeygen:      "keygen",
		CryptoFunctionEncrypt:     "encrypt",
		CryptoFunctionDecrypt:     "decrypt",
		CryptoFunctionDigest:      "digest",
		CryptoFunctionTag:         "tag",
		CryptoFunctionSign:        "sign",
		CryptoFunctionVerify:      "verify",
		CryptoFunctionKeyderive:   "keyderive",
		CryptoFunctionEncapsulate: "encapsulate",
		CryptoFunctionDecapsulate: "decapsulate",
		CryptoFunctionOther:       "other",
		CryptoFunctionUnknown:     "unknown",
	}
	for f, expected := range functions {
		if string(f) != expected {
			t.Errorf("CryptoFunction: expected %q, got %q", expected, string(f))
		}
	}

	// RelatedCryptoMaterialType enum values
	materialTypes := map[RelatedCryptoMaterialType]string{
		RelatedCryptoMaterialTypePrivateKey:           "private-key",
		RelatedCryptoMaterialTypePublicKey:            "public-key",
		RelatedCryptoMaterialTypeSecretKey:            "secret-key",
		RelatedCryptoMaterialTypeKey:                  "key",
		RelatedCryptoMaterialTypeCiphertext:           "ciphertext",
		RelatedCryptoMaterialTypeSignature:            "signature",
		RelatedCryptoMaterialTypeDigest:               "digest",
		RelatedCryptoMaterialTypeInitializationVector: "initialization-vector",
		RelatedCryptoMaterialTypeNonce:                "nonce",
		RelatedCryptoMaterialTypeSeed:                 "seed",
		RelatedCryptoMaterialTypeSalt:                 "salt",
		RelatedCryptoMaterialTypeSharedSecret:         "shared-secret",
		RelatedCryptoMaterialTypeTag:                  "tag",
		RelatedCryptoMaterialTypeAdditionalData:       "additional-data",
		RelatedCryptoMaterialTypePassword:             "password",
		RelatedCryptoMaterialTypeCredential:           "credential",
		RelatedCryptoMaterialTypeToken:                "token",
		RelatedCryptoMaterialTypeOther:                "other",
		RelatedCryptoMaterialTypeUnknown:              "unknown",
	}
	for mt, expected := range materialTypes {
		if string(mt) != expected {
			t.Errorf("RelatedCryptoMaterialType: expected %q, got %q", expected, string(mt))
		}
	}

	// RelatedCryptoMaterialState enum values
	materialStates := map[RelatedCryptoMaterialState]string{
		RelatedCryptoMaterialStatePreActivation: "pre-activation",
		RelatedCryptoMaterialStateActive:        "active",
		RelatedCryptoMaterialStateSuspended:     "suspended",
		RelatedCryptoMaterialStateDeactivated:   "deactivated",
		RelatedCryptoMaterialStateCompromised:   "compromised",
		RelatedCryptoMaterialStateDestroyed:     "destroyed",
	}
	for ms, expected := range materialStates {
		if string(ms) != expected {
			t.Errorf("RelatedCryptoMaterialState: expected %q, got %q", expected, string(ms))
		}
	}

	// AlgorithmFamily - spot check a representative set using official CycloneDX 1.7 values
	algorithmFamilies := map[AlgorithmFamily]string{
		AlgorithmFamilyAES:     "AES",
		AlgorithmFamilyECDSA:   "ECDSA",
		AlgorithmFamilyECDH:    "ECDH",
		AlgorithmFamilySHA2:    "SHA-2",
		AlgorithmFamilyMLKEM:   "ML-KEM",
		AlgorithmFamilyMLDSA:   "ML-DSA",
		AlgorithmFamilySLHDSA:  "SLH-DSA",
		AlgorithmFamilyChaCha20: "ChaCha20",
		AlgorithmFamilyArgon2:  "Argon2",
		AlgorithmFamilyHKDF:    "HKDF",
		AlgorithmFamilyBLAKE3:  "BLAKE3",
		AlgorithmFamilyScrypt:  "scrypt",
		AlgorithmFamilyBcrypt:  "bcrypt",
	}
	for af, expected := range algorithmFamilies {
		if string(af) != expected {
			t.Errorf("AlgorithmFamily: expected %q, got %q", expected, string(af))
		}
	}
}

func TestCryptoPropertiesJSONCamelCaseKeys(t *testing.T) {
	cp := CryptoProperties{
		AssetType: "algorithm",
		AlgorithmProperties: &AlgorithmProperties{
			Primitive:                PrimitiveBlockCipher,
			AlgorithmFamily:         AlgorithmFamilyAES,
			ParameterSetIdentifier:  "256",
			ExecutionEnvironment:    "software",
			ImplementationPlatform:  "x86_64",
			CertificationLevels:     []string{"FIPS 140-3 Level 1"},
			Mode:                    ModeGCM,
			Padding:                 PaddingPKCS7,
			CryptoFunctions:         []CryptoFunction{CryptoFunctionEncrypt},
			ClassicalSecurityLevel:   256,
			NistQuantumSecurityLevel: 1,
		},
		OID: "2.16.840.1.101.3.4.1.46",
	}

	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	// Check top-level camelCase keys
	expectedTopKeys := []string{"assetType", "algorithmProperties", "oid"}
	for _, key := range expectedTopKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected top-level JSON key %q not found in output: %s", key, string(data))
		}
	}

	// Verify no snake_case keys exist at top level
	snakeCaseKeys := []string{"asset_type", "algorithm_properties"}
	for _, key := range snakeCaseKeys {
		if _, ok := raw[key]; ok {
			t.Errorf("unexpected snake_case key %q found in JSON output", key)
		}
	}

	// Check nested algorithmProperties keys
	var algProps map[string]json.RawMessage
	if err := json.Unmarshal(raw["algorithmProperties"], &algProps); err != nil {
		t.Fatalf("failed to unmarshal algorithmProperties: %v", err)
	}

	expectedAlgKeys := []string{
		"primitive", "algorithmFamily", "parameterSetIdentifier",
		"executionEnvironment", "implementationPlatform", "certificationLevel",
		"mode", "padding", "cryptoFunctions",
		"classicalSecurityLevel", "nistQuantumSecurityLevel",
	}
	for _, key := range expectedAlgKeys {
		if _, ok := algProps[key]; !ok {
			t.Errorf("expected algorithmProperties JSON key %q not found", key)
		}
	}
}

func TestCryptoPropertiesOmitEmpty(t *testing.T) {
	// A minimal CryptoProperties with only AssetType should omit nil/empty fields.
	cp := CryptoProperties{
		AssetType: "algorithm",
	}

	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	// AssetType is required and should always be present
	if _, ok := raw["assetType"]; !ok {
		t.Error("assetType should always be present")
	}

	// Optional fields should be omitted
	omittedKeys := []string{
		"algorithmProperties", "certificateProperties",
		"protocolProperties", "relatedCryptoMaterialProperties", "oid",
	}
	for _, key := range omittedKeys {
		if _, ok := raw[key]; ok {
			t.Errorf("expected key %q to be omitted when nil/empty, but it was present", key)
		}
	}
}
