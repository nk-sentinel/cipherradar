package output

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// algorithmFamilyMap normalizes internal lowercase algorithm family values
// to the official CycloneDX 1.7 schema enum values.
var algorithmFamilyMap = map[string]cyclonedx17.AlgorithmFamily{
	"aes":              cyclonedx17.AlgorithmFamilyAES,
	"rsaes-oaep":       cyclonedx17.AlgorithmFamilyRSAES_OAEP,
	"rsaes-pkcs1":      cyclonedx17.AlgorithmFamilyRSAES_PKCS1,
	"rsassa-pkcs1":     cyclonedx17.AlgorithmFamilyRSASSA_PKCS1,
	"rsassa-pss":       cyclonedx17.AlgorithmFamilyRSASSA_PSS,
	"rsa":              cyclonedx17.AlgorithmFamilyRSASSA_PKCS1, // map generic "rsa" to RSASSA-PKCS1
	"hmac":             cyclonedx17.AlgorithmFamilyHMAC,
	"dsa":              cyclonedx17.AlgorithmFamilyDSA,
	"ffdh":             cyclonedx17.AlgorithmFamilyFFDH,
	"dh":               cyclonedx17.AlgorithmFamilyFFDH, // map generic "dh" to FFDH
	"ecdsa":            cyclonedx17.AlgorithmFamilyECDSA,
	"ecdh":             cyclonedx17.AlgorithmFamilyECDH,
	"ecies":            cyclonedx17.AlgorithmFamilyECIES,
	"ec":               cyclonedx17.AlgorithmFamilyECDSA, // map generic "ec" to ECDSA
	"eddsa":            cyclonedx17.AlgorithmFamilyEdDSA,
	"ed25519":          cyclonedx17.AlgorithmFamilyEdDSA,
	"ed448":            cyclonedx17.AlgorithmFamilyEdDSA,
	"x25519":           cyclonedx17.AlgorithmFamilyECDH,
	"x448":             cyclonedx17.AlgorithmFamilyECDH,
	"des":              cyclonedx17.AlgorithmFamilyDES,
	"3des":             cyclonedx17.AlgorithmFamily3DES,
	"blowfish":         cyclonedx17.AlgorithmFamilyBlowfish,
	"chacha":           cyclonedx17.AlgorithmFamilyChaCha,
	"chacha20":         cyclonedx17.AlgorithmFamilyChaCha20,
	"poly1305":         cyclonedx17.AlgorithmFamilyPoly1305,
	"camellia":         cyclonedx17.AlgorithmFamilyCAMELLIA,
	"aria":             cyclonedx17.AlgorithmFamilyARIA,
	"sm2":              cyclonedx17.AlgorithmFamilySM2,
	"sm3":              cyclonedx17.AlgorithmFamilySM3,
	"sm4":              cyclonedx17.AlgorithmFamilySM4,
	"ml-kem":           cyclonedx17.AlgorithmFamilyMLKEM,
	"ml-dsa":           cyclonedx17.AlgorithmFamilyMLDSA,
	"slh-dsa":          cyclonedx17.AlgorithmFamilySLHDSA,
	"bike":             cyclonedx17.AlgorithmFamilyBIKE,
	"hqc":              cyclonedx17.AlgorithmFamilyHQC,
	"kyber":            cyclonedx17.AlgorithmFamilyMLKEM,
	"dilithium":        cyclonedx17.AlgorithmFamilyMLDSA,
	"sphincs":          cyclonedx17.AlgorithmFamilySLHDSA,
	"falcon":           cyclonedx17.AlgorithmFamilyMLDSA,
	"classic-mceliece": cyclonedx17.AlgorithmFamilyMLKEM,
	"frodokem":         cyclonedx17.AlgorithmFamilyMLKEM,
	"ntru":             cyclonedx17.AlgorithmFamilyMLKEM,
	"saber":            cyclonedx17.AlgorithmFamilyMLKEM,
	"md2":              cyclonedx17.AlgorithmFamilyMD2,
	"md4":              cyclonedx17.AlgorithmFamilyMD4,
	"md5":              cyclonedx17.AlgorithmFamilyMD5,
	"sha":              cyclonedx17.AlgorithmFamilySHA2,
	"sha1":             cyclonedx17.AlgorithmFamilySHA1,
	"sha-1":            cyclonedx17.AlgorithmFamilySHA1,
	"sha2":             cyclonedx17.AlgorithmFamilySHA2,
	"sha-2":            cyclonedx17.AlgorithmFamilySHA2,
	"sha3":             cyclonedx17.AlgorithmFamilySHA3,
	"sha-3":            cyclonedx17.AlgorithmFamilySHA3,
	"blake2":           cyclonedx17.AlgorithmFamilyBLAKE2,
	"blake3":           cyclonedx17.AlgorithmFamilyBLAKE3,
	"rc2":              cyclonedx17.AlgorithmFamilyRC2,
	"rc4":              cyclonedx17.AlgorithmFamilyRC4,
	"rc5":              cyclonedx17.AlgorithmFamilyRC5,
	"rc6":              cyclonedx17.AlgorithmFamilyRC6,
	"idea":             cyclonedx17.AlgorithmFamilyIDEA,
	"cast":             cyclonedx17.AlgorithmFamilyCAST5,
	"cast5":            cyclonedx17.AlgorithmFamilyCAST5,
	"cast6":            cyclonedx17.AlgorithmFamilyCAST6,
	"twofish":          cyclonedx17.AlgorithmFamilyTwofish,
	"serpent":          cyclonedx17.AlgorithmFamilySerpent,
	"seed":             cyclonedx17.AlgorithmFamilySEED,
	"ripemd":           cyclonedx17.AlgorithmFamilyRIPEMD,
	"whirlpool":        cyclonedx17.AlgorithmFamilyWhirlpool,
	"cmac":             cyclonedx17.AlgorithmFamilyCMACFamily,
	"kmac":             cyclonedx17.AlgorithmFamilyKMAC,
	"hkdf":             cyclonedx17.AlgorithmFamilyHKDF,
	"pbkdf1":           cyclonedx17.AlgorithmFamilyPBKDF1,
	"pbkdf2":           cyclonedx17.AlgorithmFamilyPBKDF2,
	"scrypt":           cyclonedx17.AlgorithmFamilyScrypt,
	"bcrypt":           cyclonedx17.AlgorithmFamilyBcrypt,
	"argon2":           cyclonedx17.AlgorithmFamilyArgon2,
	"gost":             cyclonedx17.AlgorithmFamilyGOST,
	"salsa20":          cyclonedx17.AlgorithmFamilySalsa20,
	// Map specific algorithm variants to their parent family.
	"sha-256":  cyclonedx17.AlgorithmFamilySHA2,
	"sha-384":  cyclonedx17.AlgorithmFamilySHA2,
	"sha-512":  cyclonedx17.AlgorithmFamilySHA2,
	"sha256":   cyclonedx17.AlgorithmFamilySHA2,
	"sha384":   cyclonedx17.AlgorithmFamilySHA2,
	"sha512":   cyclonedx17.AlgorithmFamilySHA2,
	"sha3-256": cyclonedx17.AlgorithmFamilySHA3,
	"sha3-384": cyclonedx17.AlgorithmFamilySHA3,
	"sha3-512": cyclonedx17.AlgorithmFamilySHA3,
	"blake2b":  cyclonedx17.AlgorithmFamilyBLAKE2,
	"blake2s":  cyclonedx17.AlgorithmFamilyBLAKE2,
	"jwt":      cyclonedx17.AlgorithmFamilyHMAC, // JWT typically uses HMAC-based signing

	// New scanner families added during CBOMkit benchmark FN fixes.
	"fernet":         cyclonedx17.AlgorithmFamilyAES,    // Fernet wraps AES-128-CBC + HMAC-SHA256
	"concatkdf":      cyclonedx17.AlgorithmFamilyHKDF,   // ConcatKDF is a KDF like HKDF
	"concatkdf-hmac": cyclonedx17.AlgorithmFamilyHKDF,   // ConcatKDF-HMAC variant
	"x963kdf":        cyclonedx17.AlgorithmFamilyHKDF,   // ANSI X9.63 KDF
	"xsalsa20":       cyclonedx17.AlgorithmFamilySalsa20, // XSalsa20 is a Salsa20 variant
	"nacl":           cyclonedx17.AlgorithmFamilyChaCha20, // NaCl typically uses XSalsa20/ChaCha
	"aes-cmac":       cyclonedx17.AlgorithmFamilyCMACFamily,
	"3des-cmac":      cyclonedx17.AlgorithmFamilyCMACFamily,
	"ripemd160":      cyclonedx17.AlgorithmFamilyRIPEMD,
	"shake256":       cyclonedx17.AlgorithmFamilySHA3, // SHAKE is part of SHA-3 family
	"shake128":       cyclonedx17.AlgorithmFamilySHA3,
	"sha-224":        cyclonedx17.AlgorithmFamilySHA2,
	// Lowercase variants from some scanners.
	"sha256 ":  cyclonedx17.AlgorithmFamilySHA2, // trailing space from some parsers
	"sha384 ":  cyclonedx17.AlgorithmFamilySHA2,
	"sha1 ":    cyclonedx17.AlgorithmFamilySHA1,
	"md5 ":     cyclonedx17.AlgorithmFamilyMD5,
}

// normalizeAlgorithmFamily converts an internal algorithm family string to the
// official CycloneDX 1.7 schema value.
func normalizeAlgorithmFamily(internal string) cyclonedx17.AlgorithmFamily {
	key := strings.ToLower(strings.TrimSpace(internal))
	if af, ok := algorithmFamilyMap[key]; ok {
		return af
	}
	// Return as-is if no mapping exists (will fail schema validation, but
	// preserves the raw value for debugging).
	return cyclonedx17.AlgorithmFamily(internal)
}

// cryptoFunctionMap normalizes internal crypto function values to CycloneDX 1.7 schema values.
var cryptoFunctionMap = map[string]cyclonedx17.CryptoFunction{
	"generate":    cyclonedx17.CryptoFunctionGenerate,
	"keygen":      cyclonedx17.CryptoFunctionKeygen,
	"encrypt":     cyclonedx17.CryptoFunctionEncrypt,
	"decrypt":     cyclonedx17.CryptoFunctionDecrypt,
	"digest":      cyclonedx17.CryptoFunctionDigest,
	"tag":         cyclonedx17.CryptoFunctionTag,
	"keyderive":   cyclonedx17.CryptoFunctionKeyderive,
	"derive":      cyclonedx17.CryptoFunctionKeyderive, // map "derive" to "keyderive"
	"sign":        cyclonedx17.CryptoFunctionSign,
	"verify":      cyclonedx17.CryptoFunctionVerify,
	"encapsulate": cyclonedx17.CryptoFunctionEncapsulate,
	"decapsulate": cyclonedx17.CryptoFunctionDecapsulate,
	"mac":           cyclonedx17.CryptoFunctionTag,       // MAC computation maps to "tag"
	"cipher-suite":  cyclonedx17.CryptoFunctionEncrypt,  // cipher suite maps to encrypt
	"key-agreement": cyclonedx17.CryptoFunctionKeygen,   // key agreement maps to keygen
	"hash":          cyclonedx17.CryptoFunctionDigest,    // hash maps to digest
	"passwordhash":  cyclonedx17.CryptoFunctionKeyderive, // password hash is key derivation
	"keydrive":      cyclonedx17.CryptoFunctionKeyderive, // typo fix
	"other":         cyclonedx17.CryptoFunctionOther,
	"unknown":       cyclonedx17.CryptoFunctionUnknown,
}

// normalizeCryptoFunction converts an internal crypto function string to the
// official CycloneDX 1.7 schema value.
func normalizeCryptoFunction(internal string) cyclonedx17.CryptoFunction {
	key := strings.ToLower(strings.TrimSpace(internal))
	if cf, ok := cryptoFunctionMap[key]; ok {
		return cf
	}
	return cyclonedx17.CryptoFunction(internal)
}

// relatedCryptoMaterialTypeMap normalizes internal material type values.
var relatedCryptoMaterialTypeMap = map[string]cyclonedx17.RelatedCryptoMaterialType{
	"private-key":           cyclonedx17.RelatedCryptoMaterialTypePrivateKey,
	"public-key":            cyclonedx17.RelatedCryptoMaterialTypePublicKey,
	"secret-key":            cyclonedx17.RelatedCryptoMaterialTypeSecretKey,
	"key":                   cyclonedx17.RelatedCryptoMaterialTypeKey,
	"ciphertext":            cyclonedx17.RelatedCryptoMaterialTypeCiphertext,
	"signature":             cyclonedx17.RelatedCryptoMaterialTypeSignature,
	"digest":                cyclonedx17.RelatedCryptoMaterialTypeDigest,
	"iv":                    cyclonedx17.RelatedCryptoMaterialTypeInitializationVector,
	"initialization-vector": cyclonedx17.RelatedCryptoMaterialTypeInitializationVector,
	"nonce":                 cyclonedx17.RelatedCryptoMaterialTypeNonce,
	"seed":                  cyclonedx17.RelatedCryptoMaterialTypeSeed,
	"salt":                  cyclonedx17.RelatedCryptoMaterialTypeSalt,
	"shared-secret":         cyclonedx17.RelatedCryptoMaterialTypeSharedSecret,
	"tag":                   cyclonedx17.RelatedCryptoMaterialTypeTag,
	"additional-data":       cyclonedx17.RelatedCryptoMaterialTypeAdditionalData,
	"password":              cyclonedx17.RelatedCryptoMaterialTypePassword,
	"credential":            cyclonedx17.RelatedCryptoMaterialTypeCredential,
	"token":                 cyclonedx17.RelatedCryptoMaterialTypeToken,
	"other":                 cyclonedx17.RelatedCryptoMaterialTypeOther,
	"unknown":               cyclonedx17.RelatedCryptoMaterialTypeUnknown,
}

// paddingMap normalizes internal padding values to CycloneDX 1.7 schema values.
var paddingMap = map[string]cyclonedx17.Padding{
	"pkcs5":        cyclonedx17.PaddingPKCS5,
	"pkcs7":        cyclonedx17.PaddingPKCS7,
	"pkcs1v15":     cyclonedx17.PaddingPKCS1v15,
	"oaep":         cyclonedx17.PaddingOAEP,
	"raw":          cyclonedx17.PaddingRaw,
	"nopadding":    cyclonedx17.PaddingRaw,    // no padding = raw
	"none":         cyclonedx17.PaddingRaw,    // no padding = raw
	"pkcs5padding":                    cyclonedx17.PaddingPKCS5,    // Java-style name
	"pkcs7padding":                    cyclonedx17.PaddingPKCS7,    // Java-style name
	"pkcs1padding":                    cyclonedx17.PaddingPKCS1v15, // Java RSA default
	"oaepwithsha-256andmgf1padding":   cyclonedx17.PaddingOAEP,    // Java OAEP full name
	"oaepwithsha-1andmgf1padding":     cyclonedx17.PaddingOAEP,
	"other":                           cyclonedx17.PaddingOther,
	"unknown":                         cyclonedx17.PaddingUnknown,
}

// normalizePadding converts an internal padding string to the
// official CycloneDX 1.7 schema value.
func normalizePadding(internal string) cyclonedx17.Padding {
	key := strings.ToLower(strings.TrimSpace(internal))
	if p, ok := paddingMap[key]; ok {
		return p
	}
	return cyclonedx17.Padding(internal)
}

// modeMap normalizes internal cipher mode values to CycloneDX 1.7 schema values.
var modeMap = map[string]cyclonedx17.Mode{
	"cbc": cyclonedx17.ModeCBC,
	"ecb": cyclonedx17.ModeECB,
	"ccm": cyclonedx17.ModeCCM,
	"gcm": cyclonedx17.ModeGCM,
	"cfb": cyclonedx17.ModeCFB,
	"ofb": cyclonedx17.ModeOFB,
	"ctr": cyclonedx17.ModeCTR,
	// Non-standard modes map to "other".
	"eax": cyclonedx17.ModeOther,
	"xts": cyclonedx17.ModeOther,
	"siv": cyclonedx17.ModeOther,
	"ocb": cyclonedx17.ModeOther,
}

// normalizeMode converts an internal mode string to the CycloneDX 1.7 schema value.
func normalizeMode(internal string) cyclonedx17.Mode {
	if internal == "" {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(internal))
	if m, ok := modeMap[key]; ok {
		return m
	}
	return cyclonedx17.ModeOther
}

// primitiveMap normalizes internal primitive values to CycloneDX 1.7 schema values.
var primitiveMap = map[string]cyclonedx17.Primitive{
	"block-cipher":   cyclonedx17.PrimitiveBlockCipher,
	"stream-cipher":  cyclonedx17.PrimitiveStreamCipher,
	"hash":           cyclonedx17.PrimitiveHash,
	"mac":            cyclonedx17.PrimitiveMAC,
	"signature":      cyclonedx17.PrimitiveSignature,
	"pke":            cyclonedx17.PrimitivePKE,
	"kdf":            cyclonedx17.PrimitiveKDF,
	"key-agree":      cyclonedx17.PrimitiveKeyAgree,
	"key-exchange":   cyclonedx17.PrimitiveKeyAgree, // normalize to CycloneDX name
	"kem":            cyclonedx17.PrimitiveKEM,
	"ae":             cyclonedx17.PrimitiveAE,
	"aead":           cyclonedx17.PrimitiveAE, // alias
	"xof":            cyclonedx17.PrimitiveXOF,
	"drbg":           cyclonedx17.PrimitiveDRBG,
	"combiner":       cyclonedx17.PrimitiveCombiner,
	"key-wrap":       cyclonedx17.PrimitiveKeyWrap,
	"other":          cyclonedx17.PrimitiveOther,
	"unknown":        cyclonedx17.PrimitiveUnknown,
	// Common aliases.
	"protocol":       cyclonedx17.PrimitiveOther,
}

// normalizePrimitive converts an internal primitive string to the CycloneDX 1.7 schema value.
func normalizePrimitive(internal string) cyclonedx17.Primitive {
	if internal == "" {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(internal))
	if p, ok := primitiveMap[key]; ok {
		return p
	}
	return cyclonedx17.PrimitiveOther
}

// normalizeRelatedCryptoMaterialType converts an internal material type to the
// official CycloneDX 1.7 schema value.
func normalizeRelatedCryptoMaterialType(internal string) cyclonedx17.RelatedCryptoMaterialType {
	if mt, ok := relatedCryptoMaterialTypeMap[strings.ToLower(internal)]; ok {
		return mt
	}
	return cyclonedx17.RelatedCryptoMaterialType(internal)
}

// BOM represents a complete CycloneDX 1.7 CBOM document.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	Version      int         `json:"version"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Metadata     *Metadata   `json:"metadata,omitempty"`
	Components   []Component `json:"components,omitempty"`
}

// Metadata for the BOM.
type Metadata struct {
	Timestamp string `json:"timestamp,omitempty"`
	Tools     []Tool `json:"tools,omitempty"`
}

// Tool represents a tool that generated or contributed to the BOM.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor,omitempty"`
}

// Component represents a CycloneDX component with cryptoProperties.
type Component struct {
	Type             string                       `json:"type"`
	BOMRef           string                       `json:"bom-ref,omitempty"`
	Name             string                       `json:"name"`
	Description      string                       `json:"description,omitempty"`
	CryptoProperties *cyclonedx17.CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence                    `json:"evidence,omitempty"`
}

// Evidence captures where a component was detected.
type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence pinpoints a location in the source where the component was found.
type Occurrence struct {
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// cipherRadarVersion is the version string embedded in BOM metadata.
const cipherRadarVersion = "0.1.0"

// generateUUID4 produces a random UUID v4 string.
func generateUUID4() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// ConvertScanResult converts a types.ScanResult to a CycloneDX 1.7 BOM.
func ConvertScanResult(result *types.ScanResult) *BOM {
	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		Version:      1,
		SerialNumber: generateUUID4(),
		Metadata: &Metadata{
			Timestamp: result.StartTime.UTC().Format("2006-01-02T15:04:05Z"),
			Tools: []Tool{
				{
					Name:    "CipherRadar",
					Version: cipherRadarVersion,
					Vendor:  "nk-sentinel",
				},
			},
		},
	}

	components := make([]Component, 0, len(result.Findings))
	for i := range result.Findings {
		components = append(components, convertFinding(&result.Findings[i]))
	}

	// Sort components by bom-ref for deterministic output.
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})

	bom.Components = components
	return bom
}

// convertFinding maps a single types.Finding to a CycloneDX Component.
func convertFinding(f *types.Finding) Component {
	comp := Component{
		Type:        "cryptographic-asset",
		BOMRef:      f.ID,
		Name:        f.Name,
		Description: f.Description,
		Evidence: &Evidence{
			Occurrences: []Occurrence{
				{
					Location: f.Location.File,
					Line:     f.Location.StartLine,
				},
			},
		},
	}

	cp := convertCryptoProperties(f)
	comp.CryptoProperties = cp
	return comp
}

// convertCryptoProperties builds CycloneDX 1.7 cryptoProperties from a Finding.
func convertCryptoProperties(f *types.Finding) *cyclonedx17.CryptoProperties {
	cp := &cyclonedx17.CryptoProperties{
		AssetType: string(f.AssetType),
	}

	props := &f.Properties

	switch f.AssetType {
	case types.AssetAlgorithm:
		cp.AlgorithmProperties = convertAlgorithmProperties(props)
	case types.AssetProtocol:
		cp.ProtocolProperties = convertProtocolProperties(props)
	case types.AssetCertificate:
		cp.CertificateProperties = convertCertificateProperties(props)
	case types.AssetRelatedCryptoMaterial:
		cp.RelatedCryptoMaterialProperties = convertRelatedCryptoMaterialProperties(props)
	}

	return cp
}

// convertAlgorithmProperties maps types.CryptoProperties to CycloneDX AlgorithmProperties.
func convertAlgorithmProperties(p *types.CryptoProperties) *cyclonedx17.AlgorithmProperties {
	ap := &cyclonedx17.AlgorithmProperties{
		Primitive:                normalizePrimitive(p.Primitive),
		AlgorithmFamily:          normalizeAlgorithmFamily(p.AlgorithmFamily),
		Mode:                     normalizeMode(p.Mode),
		Padding:                  normalizePadding(p.Padding),
		ClassicalSecurityLevel:   p.ClassicalSecurity,
		NistQuantumSecurityLevel: p.NistQuantumLevel,
	}

	// For symmetric ciphers, use KeySize as classical security level if ClassicalSecurity is unset.
	if ap.ClassicalSecurityLevel == 0 && p.KeySize > 0 {
		ap.ClassicalSecurityLevel = p.KeySize
	}

	if len(p.CryptoFunctions) > 0 {
		funcs := make([]cyclonedx17.CryptoFunction, 0, len(p.CryptoFunctions))
		for _, fn := range p.CryptoFunctions {
			funcs = append(funcs, normalizeCryptoFunction(fn))
		}
		ap.CryptoFunctions = funcs
	}

	return ap
}

// convertProtocolProperties maps types.CryptoProperties to CycloneDX ProtocolProperties.
func convertProtocolProperties(p *types.CryptoProperties) *cyclonedx17.ProtocolProperties {
	pp := &cyclonedx17.ProtocolProperties{
		Type:    p.ProtocolType,
		Version: p.ProtocolVersion,
	}

	if len(p.CipherSuites) > 0 {
		suites := make([]cyclonedx17.CipherSuite, 0, len(p.CipherSuites))
		for _, name := range p.CipherSuites {
			suites = append(suites, cyclonedx17.CipherSuite{Name: name})
		}
		pp.CipherSuites = suites
	}

	return pp
}

// convertCertificateProperties maps types.CryptoProperties to CycloneDX CertificateProperties.
func convertCertificateProperties(p *types.CryptoProperties) *cyclonedx17.CertificateProperties {
	return &cyclonedx17.CertificateProperties{
		SubjectName:       p.SubjectName,
		IssuerName:        p.IssuerName,
		NotValidBefore:    p.NotValidBefore,
		NotValidAfter:     p.NotValidAfter,
		CertificateFormat: p.CertificateFormat,
	}
}

// convertRelatedCryptoMaterialProperties maps types.CryptoProperties to CycloneDX RelatedCryptoMaterialProperties.
func convertRelatedCryptoMaterialProperties(p *types.CryptoProperties) *cyclonedx17.RelatedCryptoMaterialProperties {
	return &cyclonedx17.RelatedCryptoMaterialProperties{
		Type:  normalizeRelatedCryptoMaterialType(p.MaterialType),
		State: cyclonedx17.RelatedCryptoMaterialState(p.State),
		Size:  p.MaterialSize,
	}
}
