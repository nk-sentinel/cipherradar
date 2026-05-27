package output

import (
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
)

// validPrimitives is the CycloneDX 1.7 algorithmProperties.primitive closed set.
var validPrimitives = map[cyclonedx17.Primitive]bool{
	cyclonedx17.PrimitiveDRBG: true, cyclonedx17.PrimitiveMAC: true,
	cyclonedx17.PrimitiveBlockCipher: true, cyclonedx17.PrimitiveStreamCipher: true,
	cyclonedx17.PrimitiveSignature: true, cyclonedx17.PrimitiveHash: true,
	cyclonedx17.PrimitivePKE: true, cyclonedx17.PrimitiveXOF: true,
	cyclonedx17.PrimitiveKDF: true, cyclonedx17.PrimitiveKeyAgree: true,
	cyclonedx17.PrimitiveKEM: true, cyclonedx17.PrimitiveAE: true,
	cyclonedx17.PrimitiveCombiner: true, cyclonedx17.PrimitiveKeyWrap: true,
	cyclonedx17.PrimitiveOther: true, cyclonedx17.PrimitiveUnknown: true,
}

// validAssetTypes is the CycloneDX 1.7 cryptoProperties.assetType closed set.
// IMPORTANT: "library" is NOT in this set — see ADR-040.
var validAssetTypes = map[string]bool{
	"algorithm": true, "certificate": true,
	"protocol": true, "related-crypto-material": true,
}

var validModes = map[cyclonedx17.Mode]bool{
	cyclonedx17.ModeCBC: true, cyclonedx17.ModeECB: true, cyclonedx17.ModeCCM: true,
	cyclonedx17.ModeGCM: true, cyclonedx17.ModeCFB: true, cyclonedx17.ModeOFB: true,
	cyclonedx17.ModeCTR: true, cyclonedx17.ModeOther: true, cyclonedx17.ModeUnknown: true,
}

var validPaddings = map[cyclonedx17.Padding]bool{
	cyclonedx17.PaddingPKCS5: true, cyclonedx17.PaddingPKCS7: true,
	cyclonedx17.PaddingPKCS1v15: true, cyclonedx17.PaddingOAEP: true,
	cyclonedx17.PaddingRaw: true, cyclonedx17.PaddingOther: true,
	cyclonedx17.PaddingUnknown: true,
}

var validCryptoFunctions = map[cyclonedx17.CryptoFunction]bool{
	cyclonedx17.CryptoFunctionGenerate: true, cyclonedx17.CryptoFunctionKeygen: true,
	cyclonedx17.CryptoFunctionEncrypt: true, cyclonedx17.CryptoFunctionDecrypt: true,
	cyclonedx17.CryptoFunctionDigest: true, cyclonedx17.CryptoFunctionTag: true,
	cyclonedx17.CryptoFunctionKeyderive: true, cyclonedx17.CryptoFunctionSign: true,
	cyclonedx17.CryptoFunctionVerify: true, cyclonedx17.CryptoFunctionEncapsulate: true,
	cyclonedx17.CryptoFunctionDecapsulate: true, cyclonedx17.CryptoFunctionOther: true,
	cyclonedx17.CryptoFunctionUnknown: true,
}

var validRelatedMaterialTypes = map[cyclonedx17.RelatedCryptoMaterialType]bool{
	cyclonedx17.RelatedCryptoMaterialTypePrivateKey:           true,
	cyclonedx17.RelatedCryptoMaterialTypePublicKey:            true,
	cyclonedx17.RelatedCryptoMaterialTypeSecretKey:            true,
	cyclonedx17.RelatedCryptoMaterialTypeKey:                  true,
	cyclonedx17.RelatedCryptoMaterialTypeCiphertext:           true,
	cyclonedx17.RelatedCryptoMaterialTypeSignature:            true,
	cyclonedx17.RelatedCryptoMaterialTypeDigest:               true,
	cyclonedx17.RelatedCryptoMaterialTypeInitializationVector: true,
	cyclonedx17.RelatedCryptoMaterialTypeNonce:                true,
	cyclonedx17.RelatedCryptoMaterialTypeSeed:                 true,
	cyclonedx17.RelatedCryptoMaterialTypeSalt:                 true,
	cyclonedx17.RelatedCryptoMaterialTypeSharedSecret:         true,
	cyclonedx17.RelatedCryptoMaterialTypeTag:                  true,
	cyclonedx17.RelatedCryptoMaterialTypeAdditionalData:       true,
	cyclonedx17.RelatedCryptoMaterialTypePassword:             true,
	cyclonedx17.RelatedCryptoMaterialTypeCredential:           true,
	cyclonedx17.RelatedCryptoMaterialTypeToken:                true,
	cyclonedx17.RelatedCryptoMaterialTypeOther:                true,
	cyclonedx17.RelatedCryptoMaterialTypeUnknown:              true,
}

// validAlgorithmFamilies is the CycloneDX 1.7 algorithmProperties.algorithmFamily closed set.
var validAlgorithmFamilies = map[cyclonedx17.AlgorithmFamily]bool{
	cyclonedx17.AlgorithmFamilyAES: true, cyclonedx17.AlgorithmFamilyRSAES_OAEP: true,
	cyclonedx17.AlgorithmFamilyRSAES_PKCS1: true, cyclonedx17.AlgorithmFamilyRSASSA_PKCS1: true,
	cyclonedx17.AlgorithmFamilyRSASSA_PSS: true, cyclonedx17.AlgorithmFamilyHMAC: true,
	cyclonedx17.AlgorithmFamilyDSA: true, cyclonedx17.AlgorithmFamilyFFDH: true,
	cyclonedx17.AlgorithmFamilyECDSA: true, cyclonedx17.AlgorithmFamilyECDH: true,
	cyclonedx17.AlgorithmFamilyECIES: true, cyclonedx17.AlgorithmFamilyEdDSA: true,
	cyclonedx17.AlgorithmFamilyDES: true, cyclonedx17.AlgorithmFamily3DES: true,
	cyclonedx17.AlgorithmFamilyBlowfish: true, cyclonedx17.AlgorithmFamilyChaCha: true,
	cyclonedx17.AlgorithmFamilyChaCha20: true, cyclonedx17.AlgorithmFamilyPoly1305: true,
	cyclonedx17.AlgorithmFamilyCAMELLIA: true, cyclonedx17.AlgorithmFamilyARIA: true,
	cyclonedx17.AlgorithmFamilySM2: true, cyclonedx17.AlgorithmFamilySM3: true,
	cyclonedx17.AlgorithmFamilySM4: true, cyclonedx17.AlgorithmFamilyMLKEM: true,
	cyclonedx17.AlgorithmFamilyMLDSA: true, cyclonedx17.AlgorithmFamilySLHDSA: true,
	cyclonedx17.AlgorithmFamilyBIKE: true, cyclonedx17.AlgorithmFamilyHQC: true,
	cyclonedx17.AlgorithmFamilyMD2: true, cyclonedx17.AlgorithmFamilyMD4: true,
	cyclonedx17.AlgorithmFamilyMD5: true, cyclonedx17.AlgorithmFamilySHA1: true,
	cyclonedx17.AlgorithmFamilySHA2: true, cyclonedx17.AlgorithmFamilySHA3: true,
	cyclonedx17.AlgorithmFamilyBLAKE2: true, cyclonedx17.AlgorithmFamilyBLAKE3: true,
	cyclonedx17.AlgorithmFamilyRC2: true, cyclonedx17.AlgorithmFamilyRC4: true,
	cyclonedx17.AlgorithmFamilyRC5: true, cyclonedx17.AlgorithmFamilyRC6: true,
	cyclonedx17.AlgorithmFamilyIDEA: true, cyclonedx17.AlgorithmFamilyCAST5: true,
	cyclonedx17.AlgorithmFamilyCAST6: true, cyclonedx17.AlgorithmFamilyTwofish: true,
	cyclonedx17.AlgorithmFamilySerpent: true, cyclonedx17.AlgorithmFamilySEED: true,
	cyclonedx17.AlgorithmFamilyRIPEMD: true, cyclonedx17.AlgorithmFamilyWhirlpool: true,
	cyclonedx17.AlgorithmFamilyCMACFamily: true, cyclonedx17.AlgorithmFamilyKMAC: true,
	cyclonedx17.AlgorithmFamilyHKDF: true, cyclonedx17.AlgorithmFamilyPBKDF1: true,
	cyclonedx17.AlgorithmFamilyPBKDF2: true, cyclonedx17.AlgorithmFamilyPBES1: true,
	cyclonedx17.AlgorithmFamilyPBES2: true, cyclonedx17.AlgorithmFamilyPBMAC1: true,
	cyclonedx17.AlgorithmFamilySP800_108: true, cyclonedx17.AlgorithmFamilyScrypt: true,
	cyclonedx17.AlgorithmFamilyBcrypt: true, cyclonedx17.AlgorithmFamilyArgon2: true,
	cyclonedx17.AlgorithmFamilyElGamal: true, cyclonedx17.AlgorithmFamilyGOST: true,
	cyclonedx17.AlgorithmFamilyLMS: true, cyclonedx17.AlgorithmFamilyXMSS: true,
	cyclonedx17.AlgorithmFamilyHPKE: true, cyclonedx17.AlgorithmFamilyBLS: true,
	cyclonedx17.AlgorithmFamilySipHash: true, cyclonedx17.AlgorithmFamilyUMAC: true,
	cyclonedx17.AlgorithmFamilySkipjack: true, cyclonedx17.AlgorithmFamilyFortuna: true,
	cyclonedx17.AlgorithmFamilyCTR_DRBG: true, cyclonedx17.AlgorithmFamilyHMAC_DRBG: true,
	cyclonedx17.AlgorithmFamilyHash_DRBG: true, cyclonedx17.AlgorithmFamilySalsa20: true,
	cyclonedx17.AlgorithmFamilyRABBIT: true, cyclonedx17.AlgorithmFamilyHC: true,
	cyclonedx17.AlgorithmFamilySNOW3G: true, cyclonedx17.AlgorithmFamilyZUC: true,
	cyclonedx17.AlgorithmFamilyCMEA: true, cyclonedx17.AlgorithmFamilyA5_1: true,
	cyclonedx17.AlgorithmFamilyA5_2: true, cyclonedx17.AlgorithmFamily3GPP_XOR: true,
	cyclonedx17.AlgorithmFamilyMILENAGE: true, cyclonedx17.AlgorithmFamilyTUAK: true,
	cyclonedx17.AlgorithmFamilyAscon: true, cyclonedx17.AlgorithmFamilySM9: true,
	cyclonedx17.AlgorithmFamilyMQV: true, cyclonedx17.AlgorithmFamilyOPAQUE: true,
	cyclonedx17.AlgorithmFamilySPAKE2: true, cyclonedx17.AlgorithmFamilySPAKE2PLUS: true,
	cyclonedx17.AlgorithmFamilySRP: true, cyclonedx17.AlgorithmFamilyJPAKE: true,
	cyclonedx17.AlgorithmFamilyX3DH: true, cyclonedx17.AlgorithmFamilyEAP_AKA: true,
	cyclonedx17.AlgorithmFamilyEAP_AKA_PRIME: true, cyclonedx17.AlgorithmFamily5G_AKA: true,
	cyclonedx17.AlgorithmFamilyIKE_PRF: true,
}

// maxExamples is how many example violations the tally records for log output.
const maxExamples = 10

// validationTally counts normalization fall-throughs during ConvertScanResult.
// Non-zero values indicate the scanner emitted something outside the CycloneDX 1.7
// closed sets; the converter still produced safe output (PrimitiveOther / etc.)
// but the original value was lost.
type validationTally struct {
	Primitives           int
	AssetTypes           int
	AlgorithmFamilies    int
	Modes                int
	Paddings             int
	CryptoFunctions      int
	RelatedMaterialTypes int
	Total                int
	Examples             []string // first maxExamples violations, formatted "<field>=<value>"
}

func (v *validationTally) record(field, value string) {
	v.Total++
	if len(v.Examples) < maxExamples {
		v.Examples = append(v.Examples, fmt.Sprintf("%s=%q", field, value))
	}
}

func (v *validationTally) recordPrimitive(value string) { v.Primitives++; v.record("primitive", value) }
func (v *validationTally) recordAssetType(value string) { v.AssetTypes++; v.record("assetType", value) }
func (v *validationTally) recordAlgorithmFamily(value string) {
	v.AlgorithmFamilies++
	v.record("algorithmFamily", value)
}
func (v *validationTally) recordMode(value string)    { v.Modes++; v.record("mode", value) }
func (v *validationTally) recordPadding(value string) { v.Paddings++; v.record("padding", value) }
func (v *validationTally) recordCryptoFunction(value string) {
	v.CryptoFunctions++
	v.record("cryptoFunction", value)
}
func (v *validationTally) recordMaterialType(value string) {
	v.RelatedMaterialTypes++
	v.record("relatedCryptoMaterialType", value)
}

// Summary returns a single-line stderr summary of violations.
func (v *validationTally) Summary() string {
	if v.Total == 0 {
		return ""
	}
	parts := []string{}
	add := func(label string, n int) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	add("primitive", v.Primitives)
	add("assetType", v.AssetTypes)
	add("algorithmFamily", v.AlgorithmFamilies)
	add("mode", v.Modes)
	add("padding", v.Paddings)
	add("cryptoFunction", v.CryptoFunctions)
	add("relatedCryptoMaterialType", v.RelatedMaterialTypes)
	return fmt.Sprintf("%d normalization violations during CycloneDX 1.7 conversion (%s); examples: %s",
		v.Total, strings.Join(parts, ", "), strings.Join(v.Examples, ", "))
}
