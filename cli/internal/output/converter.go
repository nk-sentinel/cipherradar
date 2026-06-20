package output

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
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
	"fernet":         cyclonedx17.AlgorithmFamilyAES,      // Fernet wraps AES-128-CBC + HMAC-SHA256
	"concatkdf":      cyclonedx17.AlgorithmFamilyHKDF,     // ConcatKDF is a KDF like HKDF
	"concatkdf-hmac": cyclonedx17.AlgorithmFamilyHKDF,     // ConcatKDF-HMAC variant
	"x963kdf":        cyclonedx17.AlgorithmFamilyHKDF,     // ANSI X9.63 KDF
	"xsalsa20":       cyclonedx17.AlgorithmFamilySalsa20,  // XSalsa20 is a Salsa20 variant
	"nacl":           cyclonedx17.AlgorithmFamilyChaCha20, // NaCl typically uses XSalsa20/ChaCha
	"aes-cmac":       cyclonedx17.AlgorithmFamilyCMACFamily,
	"3des-cmac":      cyclonedx17.AlgorithmFamilyCMACFamily,
	"ripemd160":      cyclonedx17.AlgorithmFamilyRIPEMD,
	"shake256":       cyclonedx17.AlgorithmFamilySHA3, // SHAKE is part of SHA-3 family
	"shake128":       cyclonedx17.AlgorithmFamilySHA3,
	"sha-224":        cyclonedx17.AlgorithmFamilySHA2,
	// Lowercase variants from some scanners.
	"sha256 ": cyclonedx17.AlgorithmFamilySHA2, // trailing space from some parsers
	"sha384 ": cyclonedx17.AlgorithmFamilySHA2,
	"sha1 ":   cyclonedx17.AlgorithmFamilySHA1,
	"md5 ":    cyclonedx17.AlgorithmFamilyMD5,
	// Dart PointyCastle emits "fortuna" (lowercase); canonical enum is "Fortuna".
	"fortuna": cyclonedx17.AlgorithmFamilyFortuna,
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
	"generate":      cyclonedx17.CryptoFunctionGenerate,
	"keygen":        cyclonedx17.CryptoFunctionKeygen,
	"encrypt":       cyclonedx17.CryptoFunctionEncrypt,
	"decrypt":       cyclonedx17.CryptoFunctionDecrypt,
	"digest":        cyclonedx17.CryptoFunctionDigest,
	"tag":           cyclonedx17.CryptoFunctionTag,
	"keyderive":     cyclonedx17.CryptoFunctionKeyderive,
	"derive":        cyclonedx17.CryptoFunctionKeyderive, // map "derive" to "keyderive"
	"sign":          cyclonedx17.CryptoFunctionSign,
	"verify":        cyclonedx17.CryptoFunctionVerify,
	"encapsulate":   cyclonedx17.CryptoFunctionEncapsulate,
	"decapsulate":   cyclonedx17.CryptoFunctionDecapsulate,
	"mac":           cyclonedx17.CryptoFunctionTag,       // MAC computation maps to "tag"
	"cipher-suite":  cyclonedx17.CryptoFunctionEncrypt,   // cipher suite maps to encrypt
	"key-agreement": cyclonedx17.CryptoFunctionKeygen,    // key agreement maps to keygen
	"hash":          cyclonedx17.CryptoFunctionDigest,    // hash maps to digest
	"passwordhash":  cyclonedx17.CryptoFunctionKeyderive, // password hash is key derivation
	"keydrive":      cyclonedx17.CryptoFunctionKeyderive, // typo fix
	// Key-agreement aliases — scanners emit "keyagree" or "key-agree" as a function;
	// CycloneDX 1.7 has no "keyagree" function: closest equivalent is "keygen".
	"keyagree":  cyclonedx17.CryptoFunctionKeygen,
	"key-agree": cyclonedx17.CryptoFunctionKeygen,
	// PHP openssl_seal emits "seal" (authenticated encryption); maps to "encrypt".
	"seal":    cyclonedx17.CryptoFunctionEncrypt,
	"open":    cyclonedx17.CryptoFunctionDecrypt, // openssl_open is the decrypt counterpart
	"other":   cyclonedx17.CryptoFunctionOther,
	"unknown": cyclonedx17.CryptoFunctionUnknown,
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
	// Aliases: scanner tokens that normalize to a canonical CycloneDX type.
	"symmetric-key": cyclonedx17.RelatedCryptoMaterialTypeSecretKey, // CycloneDX uses "secret-key"
}

// paddingMap normalizes internal padding values to CycloneDX 1.7 schema values.
var paddingMap = map[string]cyclonedx17.Padding{
	"pkcs5":                         cyclonedx17.PaddingPKCS5,
	"pkcs7":                         cyclonedx17.PaddingPKCS7,
	"pkcs1v15":                      cyclonedx17.PaddingPKCS1v15,
	"oaep":                          cyclonedx17.PaddingOAEP,
	"raw":                           cyclonedx17.PaddingRaw,
	"nopadding":                     cyclonedx17.PaddingRaw,      // no padding = raw
	"none":                          cyclonedx17.PaddingRaw,      // no padding = raw
	"pkcs5padding":                  cyclonedx17.PaddingPKCS5,    // Java-style name
	"pkcs7padding":                  cyclonedx17.PaddingPKCS7,    // Java-style name
	"pkcs1padding":                  cyclonedx17.PaddingPKCS1v15, // Java RSA default
	"oaepwithsha-256andmgf1padding": cyclonedx17.PaddingOAEP,     // Java OAEP full name
	"oaepwithsha-1andmgf1padding":   cyclonedx17.PaddingOAEP,
	"other":                         cyclonedx17.PaddingOther,
	"unknown":                       cyclonedx17.PaddingUnknown,
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
	"block-cipher":  cyclonedx17.PrimitiveBlockCipher,
	"stream-cipher": cyclonedx17.PrimitiveStreamCipher,
	"hash":          cyclonedx17.PrimitiveHash,
	"mac":           cyclonedx17.PrimitiveMAC,
	"signature":     cyclonedx17.PrimitiveSignature,
	"pke":           cyclonedx17.PrimitivePKE,
	"kdf":           cyclonedx17.PrimitiveKDF,
	"key-agree":     cyclonedx17.PrimitiveKeyAgree,
	"key-exchange":  cyclonedx17.PrimitiveKeyAgree, // normalize to CycloneDX name
	"kem":           cyclonedx17.PrimitiveKEM,
	"ae":            cyclonedx17.PrimitiveAE,
	"aead":          cyclonedx17.PrimitiveAE, // alias
	"xof":           cyclonedx17.PrimitiveXOF,
	"drbg":          cyclonedx17.PrimitiveDRBG,
	"combiner":      cyclonedx17.PrimitiveCombiner,
	"key-wrap":      cyclonedx17.PrimitiveKeyWrap,
	"other":         cyclonedx17.PrimitiveOther,
	"unknown":       cyclonedx17.PrimitiveUnknown,
	// Common aliases.
	"protocol": cyclonedx17.PrimitiveOther,
}

// canonicalTokenPrimitive maps canonical algorithm tokens (as emitted by
// OpenGrep rule cbom-primitive metadata) to their CycloneDX 1.7 primitive.
// Used by convertAlgorithmProperties when AlgorithmPrimitive is a known
// algorithm name rather than a primitive name.
var canonicalTokenPrimitive = map[string]cyclonedx17.Primitive{
	// hash family
	"MD2": cyclonedx17.PrimitiveHash, "MD4": cyclonedx17.PrimitiveHash, "MD5": cyclonedx17.PrimitiveHash,
	"SHA-1": cyclonedx17.PrimitiveHash, "SHA-2": cyclonedx17.PrimitiveHash, "SHA-3": cyclonedx17.PrimitiveHash,
	"SHA1": cyclonedx17.PrimitiveHash, "SHA256": cyclonedx17.PrimitiveHash, "SHA384": cyclonedx17.PrimitiveHash,
	"SHA512": cyclonedx17.PrimitiveHash, "SHA-224": cyclonedx17.PrimitiveHash, "SHA-256": cyclonedx17.PrimitiveHash,
	"SHA-384": cyclonedx17.PrimitiveHash, "SHA-512": cyclonedx17.PrimitiveHash,
	"BLAKE2": cyclonedx17.PrimitiveHash, "BLAKE3": cyclonedx17.PrimitiveHash,
	"RIPEMD": cyclonedx17.PrimitiveHash, "WHIRLPOOL": cyclonedx17.PrimitiveHash,
	// block-cipher
	"AES": cyclonedx17.PrimitiveBlockCipher, "AES-128": cyclonedx17.PrimitiveBlockCipher,
	"AES-192": cyclonedx17.PrimitiveBlockCipher, "AES-256": cyclonedx17.PrimitiveBlockCipher,
	"AES-128-GCM": cyclonedx17.PrimitiveBlockCipher, "AES-256-GCM": cyclonedx17.PrimitiveBlockCipher,
	"AES-128-CBC": cyclonedx17.PrimitiveBlockCipher, "AES-256-CBC": cyclonedx17.PrimitiveBlockCipher,
	"DES": cyclonedx17.PrimitiveBlockCipher, "3DES": cyclonedx17.PrimitiveBlockCipher,
	"BLOWFISH": cyclonedx17.PrimitiveBlockCipher, "TWOFISH": cyclonedx17.PrimitiveBlockCipher,
	"CAMELLIA": cyclonedx17.PrimitiveBlockCipher, "ARIA": cyclonedx17.PrimitiveBlockCipher,
	"SEED": cyclonedx17.PrimitiveBlockCipher, "SM4": cyclonedx17.PrimitiveBlockCipher,
	"IDEA": cyclonedx17.PrimitiveBlockCipher, "CAST5": cyclonedx17.PrimitiveBlockCipher,
	"CAST6": cyclonedx17.PrimitiveBlockCipher, "SERPENT": cyclonedx17.PrimitiveBlockCipher,
	"SKIPJACK": cyclonedx17.PrimitiveBlockCipher,
	// stream-cipher
	"CHACHA20": cyclonedx17.PrimitiveStreamCipher, "CHACHA": cyclonedx17.PrimitiveStreamCipher,
	"SALSA20": cyclonedx17.PrimitiveStreamCipher, "RC4": cyclonedx17.PrimitiveStreamCipher,
	// signature
	"RSA": cyclonedx17.PrimitiveSignature, "DSA": cyclonedx17.PrimitiveSignature,
	"ECDSA": cyclonedx17.PrimitiveSignature, "EDDSA": cyclonedx17.PrimitiveSignature,
	"ED25519": cyclonedx17.PrimitiveSignature, "ED448": cyclonedx17.PrimitiveSignature,
	"ML-DSA": cyclonedx17.PrimitiveSignature, "SLH-DSA": cyclonedx17.PrimitiveSignature,
	// key-agree
	"DH": cyclonedx17.PrimitiveKeyAgree, "ECDH": cyclonedx17.PrimitiveKeyAgree,
	"X25519": cyclonedx17.PrimitiveKeyAgree, "X448": cyclonedx17.PrimitiveKeyAgree,
	// kem
	"ML-KEM": cyclonedx17.PrimitiveKEM, "BIKE": cyclonedx17.PrimitiveKEM, "HQC": cyclonedx17.PrimitiveKEM,
	// kdf
	"HKDF": cyclonedx17.PrimitiveKDF, "PBKDF1": cyclonedx17.PrimitiveKDF, "PBKDF2": cyclonedx17.PrimitiveKDF,
	"SCRYPT": cyclonedx17.PrimitiveKDF, "BCRYPT": cyclonedx17.PrimitiveKDF, "ARGON2": cyclonedx17.PrimitiveKDF,
	// mac
	"HMAC": cyclonedx17.PrimitiveMAC, "CMAC": cyclonedx17.PrimitiveMAC, "KMAC": cyclonedx17.PrimitiveMAC,
	"POLY1305": cyclonedx17.PrimitiveMAC,
	// hash family additions
	"KECCAK": cyclonedx17.PrimitiveHash, "KECCAK-256": cyclonedx17.PrimitiveHash,
	"KECCAK-512": cyclonedx17.PrimitiveHash, "TIGER": cyclonedx17.PrimitiveHash,
	"SKEIN-256": cyclonedx17.PrimitiveHash, "SKEIN-512": cyclonedx17.PrimitiveHash,
	"GOST3411": cyclonedx17.PrimitiveHash, "GOST-3411": cyclonedx17.PrimitiveHash,
	// block-cipher additions
	"AES-ECB": cyclonedx17.PrimitiveBlockCipher, "AES-CFB": cyclonedx17.PrimitiveBlockCipher,
	"AES-OFB": cyclonedx17.PrimitiveBlockCipher, "AES-CTR": cyclonedx17.PrimitiveBlockCipher,
	"AES-CCM": cyclonedx17.PrimitiveBlockCipher,
	// key-wrap
	"AES-KW": cyclonedx17.PrimitiveKeyWrap,
	// key-agree additions
	"CURVE25519": cyclonedx17.PrimitiveKeyAgree, "P-256": cyclonedx17.PrimitiveKeyAgree,
	"P-384": cyclonedx17.PrimitiveKeyAgree, "P-521": cyclonedx17.PrimitiveKeyAgree,
	// kem additions
	"CLASSIC-MCELIECE": cyclonedx17.PrimitiveKEM, "FRODOKEM": cyclonedx17.PrimitiveKEM,
	"FRODO": cyclonedx17.PrimitiveKEM, "SABER": cyclonedx17.PrimitiveKEM, "NTRU": cyclonedx17.PrimitiveKEM,
	// signature additions
	"ELGAMAL": cyclonedx17.PrimitiveSignature, "DILITHIUM": cyclonedx17.PrimitiveSignature,
	"FALCON": cyclonedx17.PrimitiveSignature, "SPHINCS+": cyclonedx17.PrimitiveSignature,
	"SPHINCS": cyclonedx17.PrimitiveSignature, "FN-DSA": cyclonedx17.PrimitiveSignature,
	"XMSS": cyclonedx17.PrimitiveSignature, "XMSS-MT": cyclonedx17.PrimitiveSignature,
	"LMS": cyclonedx17.PrimitiveSignature, "HSS": cyclonedx17.PrimitiveSignature,
	// kdf additions
	"ARGON2I": cyclonedx17.PrimitiveKDF, "ARGON2ID": cyclonedx17.PrimitiveKDF,
	"KBKDF": cyclonedx17.PrimitiveKDF, "CONCATKDF": cyclonedx17.PrimitiveKDF,
	"X963KDF": cyclonedx17.PrimitiveKDF,
	// mac additions
	"GMAC": cyclonedx17.PrimitiveMAC, "SIPHASH": cyclonedx17.PrimitiveMAC,
	"SIPHASH-128": cyclonedx17.PrimitiveMAC,
	// explicit PrimitiveOther for tokens that aren't primitives but shouldn't error
	"CRYPTO-PROVIDER-REGISTRATION": cyclonedx17.PrimitiveOther,
	// WEAK-PRNG maps to drbg — it's a (poor) PRNG variant
	"WEAK-PRNG": cyclonedx17.PrimitiveDRBG,
}

// rerouteMarker identifies AlgorithmPrimitive tokens that indicate the finding
// should be modeled as a different assetType. Returns the target assetType and
// material type (when applicable). Empty assetType means no reroute needed.
func rerouteMarker(token string) (assetType types.AssetType, materialType string) {
	switch strings.ToUpper(token) {
	case "HARDCODED-SECRET", "HARDCODE-SECRET", "HARDCODED_SECRET":
		return types.AssetRelatedCryptoMaterial, "other"
	case "PRIVATE-KEY-PEM", "PRIVATE-KEY", "PRIVATE_KEY":
		return types.AssetRelatedCryptoMaterial, "private-key"
	case "PUBLIC-KEY-PEM", "PUBLIC-KEY", "PUBLIC_KEY":
		return types.AssetRelatedCryptoMaterial, "public-key"

	// Protocol tokens (cbom-primitive: SSH, TLS, TLS-1.0, TLS-1.1, TLS-1.2,
	// TLS-1.3, SSL-3.0) belong in assetType=protocol, not algorithm.
	case "SSH", "TLS", "TLS-1.0", "TLS-1.1", "TLS-1.2", "TLS-1.3",
		"SSL", "SSL-2.0", "SSL-3.0", "DTLS", "DTLS-1.0", "DTLS-1.2", "DTLS-1.3",
		"IPSEC", "IKE", "IKEV1", "IKEV2", "SAML", "OIDC", "JWT":
		return types.AssetProtocol, ""

	// Material-only tokens belong in related-crypto-material.
	case "INITIALIZATION-VECTOR", "IV", "SYMMETRIC-KEY", "SHARED-SECRET",
		"NONCE", "SALT", "SEED", "PASSWORD", "CREDENTIAL", "TOKEN":
		// Map to the most appropriate CycloneDX RelatedCryptoMaterialType.
		// The switch in convertCryptoProperties uses materialType to populate
		// RelatedCryptoMaterialProperties.Type, which is normalized through
		// normalizeRelatedCryptoMaterialType.
		materialType := strings.ToLower(strings.ReplaceAll(token, "_", "-"))
		return types.AssetRelatedCryptoMaterial, materialType

	// Certificate tokens.
	case "CERTIFICATE", "CERTIFICATE-X509", "X509", "X.509":
		return types.AssetCertificate, ""

	// CRYPTO-LIBRARY-IMPORT is not handled here; it requires AssetType-level
	// reroute (see Task 1.3 — convertFindingTally short-circuits when
	// f.AssetType == "library").
	default:
		return "", ""
	}
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
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	Version      int          `json:"version"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Metadata     *Metadata    `json:"metadata,omitempty"`
	Components   []Component  `json:"components,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Dependency is a CycloneDX 1.7 dependency-graph edge: ref dependsOn others.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
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
	Type             string                        `json:"type"`
	BOMRef           string                        `json:"bom-ref,omitempty"`
	Name             string                        `json:"name"`
	Group            string                        `json:"group,omitempty"`
	Version          string                        `json:"version,omitempty"`
	Purl             string                        `json:"purl,omitempty"`
	Description      string                        `json:"description,omitempty"`
	CryptoProperties *cyclonedx17.CryptoProperties `json:"cryptoProperties,omitempty"`
	Properties       []Property                    `json:"properties,omitempty"`
	Evidence         *Evidence                     `json:"evidence,omitempty"`
}

// Property represents a CycloneDX name-value property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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

// AppVersion is the version string embedded in BOM metadata.
// Set by cmd package at init time from ldflags-injected Version.
// Defaults to "dev" for local builds.
var AppVersion = "dev"

// generateUUID4 produces a random UUID v4 string.
func generateUUID4() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// ConvertScanResultWithTally is like ConvertScanResult but also returns a
// validationTally counting normalization fall-throughs. Callers that want
// to surface or fail on tally totals (e.g. --strict-validate) use this.
func ConvertScanResultWithTally(result *types.ScanResult) (*BOM, validationTally) {
	var tally validationTally
	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		Version:      1,
		SerialNumber: generateUUID4(),
		Metadata: &Metadata{
			Timestamp: result.StartTime.UTC().Format("2006-01-02T15:04:05Z"),
			Tools:     []Tool{{Name: "CipherRadar", Version: AppVersion, Vendor: "nk-sentinel"}},
		},
	}
	// #30: ensure every finding with a resolvable algorithm family carries
	// quantum posture, regardless of which pass produced it. Pass-1 scanners
	// label at emit time; Pass-2 (OpenGrep) findings are labeled here. Idempotent
	// — scan.go also calls AnnotateQuantum on the pipeline so non-CBOM writers
	// (text/sarif/pdf) get the same posture; the guard skips already-labeled
	// findings, so running it again is a no-op.
	AnnotateQuantum(result)

	acc := &componentAccumulator{seenRefs: map[string]bool{}, deps: map[string][]string{}}
	for i := range result.Findings {
		f := &result.Findings[i]
		comp := convertFindingTally(f, &tally)
		acc.add(comp)
		// Certificates expand into a linked graph: the cert plus synthetic
		// signature-algorithm and subject-public-key components, wired by ref.
		if comp.CryptoProperties != nil && comp.CryptoProperties.AssetType == "certificate" {
			expandCertificateGraph(&acc.components[len(acc.components)-1], f, acc)
		}
	}
	sort.Slice(acc.components, func(i, j int) bool {
		return acc.components[i].BOMRef < acc.components[j].BOMRef
	})
	bom.Components = acc.components
	bom.Dependencies = acc.flushDependencies()
	return bom, tally
}

// componentAccumulator collects components while deduplicating shared synthetic
// components by content-addressed bom-ref, and records dependency-graph edges.
type componentAccumulator struct {
	components []Component
	seenRefs   map[string]bool
	deps       map[string][]string
}

func (a *componentAccumulator) add(c Component) {
	a.components = append(a.components, c)
	if c.BOMRef != "" {
		a.seenRefs[c.BOMRef] = true
	}
}

// addUnique appends c only if its ref has not been seen (for shared, content-
// addressed synthetic components). Returns the ref either way.
func (a *componentAccumulator) addUnique(c Component) string {
	if !a.seenRefs[c.BOMRef] {
		a.add(c)
	}
	return c.BOMRef
}

func (a *componentAccumulator) dependsOn(ref string, on ...string) {
	a.deps[ref] = append(a.deps[ref], on...)
}

func (a *componentAccumulator) flushDependencies() []Dependency {
	if len(a.deps) == 0 {
		return nil
	}
	out := make([]Dependency, 0, len(a.deps))
	for ref, on := range a.deps {
		out = append(out, Dependency{Ref: ref, DependsOn: on})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// ConvertScanResult converts a types.ScanResult to a CycloneDX 1.7 BOM.
// For tally observability, use ConvertScanResultWithTally instead.
func ConvertScanResult(result *types.ScanResult) *BOM {
	bom, _ := ConvertScanResultWithTally(result)
	return bom
}

// convertFinding maps a single types.Finding to a CycloneDX Component.
func convertFinding(f *types.Finding) Component {
	return convertFindingTally(f, nil)
}

func convertFindingTally(f *types.Finding, tally *validationTally) Component {
	// ADR-040: library findings (from opengrep cbom-library-import rules and
	// yara-x library signatures) emit as regular CycloneDX components with
	// type: library, no cryptoProperties. They are not cryptographic assets.
	if string(f.AssetType) == "library" {
		comp := Component{
			Type:        "library",
			BOMRef:      f.ID,
			Name:        f.Name,
			Description: f.Description,
			Evidence: &Evidence{
				Occurrences: []Occurrence{
					{Location: f.Location.File, Line: f.Location.StartLine},
				},
			},
			Properties: buildFindingProperties(f),
		}
		applyLibraryIdentity(&comp, f)
		return comp
	}

	// Existing cryptographic-asset path unchanged below this line.
	comp := Component{
		Type:        "cryptographic-asset",
		BOMRef:      f.ID,
		Name:        f.Name,
		Description: f.Description,
		Evidence: &Evidence{
			Occurrences: []Occurrence{
				{Location: f.Location.File, Line: f.Location.StartLine},
			},
		},
	}
	cp := convertCryptoProperties(f, tally)
	comp.CryptoProperties = cp
	comp.Properties = buildFindingProperties(f)
	// Some crypto-asset findings (e.g. PHP mcrypt) also carry a library hint —
	// attach purl/version/group without disturbing cryptoProperties.
	applyLibraryIdentity(&comp, f)
	return comp
}

// applyLibraryIdentity attaches resolved library group/version/purl (populated
// by the dependency-enrichment pass) to a component. For library components it
// also upgrades the display name to the concrete package when available.
func applyLibraryIdentity(comp *Component, f *types.Finding) {
	p := &f.Properties
	if comp.Type == "library" && p.LibraryPurl != "" && p.Library != "" {
		comp.Name = p.Library
	}
	comp.Group = p.LibraryGroup
	comp.Version = p.LibraryVersion
	comp.Purl = p.LibraryPurl
}

// buildFindingProperties creates CycloneDX properties from finding metadata.
func buildFindingProperties(f *types.Finding) []Property {
	props := []Property{
		{Name: "severity", Value: string(f.Severity)},
		{Name: "confidence", Value: string(f.Confidence)},
	}
	if f.RuleID != "" {
		props = append(props, Property{Name: "ruleId", Value: f.RuleID})
	}
	if f.Properties.Library != "" {
		props = append(props, Property{Name: "library", Value: f.Properties.Library})
	}
	if f.Properties.QuantumStatus != "" && f.Properties.QuantumStatus != types.QuantumNotApplicable {
		props = append(props, Property{Name: "quantumStatus", Value: string(f.Properties.QuantumStatus)})
		props = appendQuantumMigrationProps(props, &f.Properties)
	}
	if f.Fingerprint != "" {
		props = append(props, Property{Name: "fingerprint", Value: f.Fingerprint})
	}
	if f.Pass > 0 {
		props = append(props, Property{Name: "detectionPass", Value: fmt.Sprintf("%d", f.Pass)})
	}
	return props
}

// appendQuantumMigrationProps adds the HNDL-aware migration payload — priority,
// recommendation, and structured replacement target — as namespaced CycloneDX
// properties so downstream consumers (migration pipelines, dashboards) can act
// on them without re-deriving the quantum table. Called only when the finding
// has a definitive quantum status.
func appendQuantumMigrationProps(props []Property, p *types.CryptoProperties) []Property {
	primitive := string(resolvePrimitive(p))
	if prio := quantum.Priority(p.QuantumStatus, primitive); prio != "" {
		props = append(props, Property{Name: "cradar:quantum:priority", Value: string(prio)})
	}
	info := quantum.GetInfo(p.AlgorithmFamily)
	if info.Recommendation != "" {
		props = append(props, Property{Name: "cradar:quantum:recommendation", Value: info.Recommendation})
	}
	if info.MigrationTarget != "" {
		props = append(props, Property{Name: "cradar:quantum:migrationTarget", Value: info.MigrationTarget})
	}
	return props
}

// convertCryptoProperties builds CycloneDX 1.7 cryptoProperties from a Finding,
// applying AlgorithmPrimitive-token reroutes (HARDCODED-SECRET → related-crypto-material, etc.)
// before the assetType switch. Records violations in tally if non-nil.
func convertCryptoProperties(f *types.Finding, tally *validationTally) *cyclonedx17.CryptoProperties {
	props := &f.Properties

	// Reroute by AlgorithmPrimitive marker (Bug A fix).
	effectiveAssetType := f.AssetType
	rerouteMaterial := ""
	if props.AlgorithmPrimitive != "" {
		if at, mt := rerouteMarker(props.AlgorithmPrimitive); at != "" {
			effectiveAssetType = at
			rerouteMaterial = mt
		}
	}

	cp := &cyclonedx17.CryptoProperties{
		AssetType: string(effectiveAssetType),
	}

	switch effectiveAssetType {
	case types.AssetAlgorithm:
		cp.AlgorithmProperties = convertAlgorithmProperties(props)
	case types.AssetProtocol:
		cp.ProtocolProperties = convertProtocolProperties(props)
	case types.AssetCertificate:
		cp.CertificateProperties = convertCertificateProperties(props)
	case types.AssetRelatedCryptoMaterial:
		if rerouteMaterial != "" {
			// Reroute case: clear primitive (it was the marker) and set material type.
			cp.RelatedCryptoMaterialProperties = &cyclonedx17.RelatedCryptoMaterialProperties{
				Type: normalizeRelatedCryptoMaterialType(rerouteMaterial),
			}
			// Do NOT populate AlgorithmProperties on a rerouted finding.
		} else {
			cp.RelatedCryptoMaterialProperties = convertRelatedCryptoMaterialProperties(props)
			// Preserve existing dual-properties behavior for non-rerouted material findings.
			// When a related-crypto-material finding carries a canonical
			// algorithm token (e.g. PRIVATE-KEY-PEM emitted by the PEM-block
			// regex rules), surface it under algorithmProperties.primitive
			// too. The CycloneDX 1.7 cryptoProperties schema allows both
			// algorithmProperties and relatedCryptoMaterialProperties to be
			// present on the same block (no oneOf constraint). Downstream
			// CBOM consumers that inspect algorithmProperties.primitive can
			// then route the finding to the certs/keys bucket without
			// scanning rule IDs.
			if props.AlgorithmPrimitive != "" {
				cp.AlgorithmProperties = convertAlgorithmProperties(props)
			}
		}
	default:
		// Unknown assetType — record violation and emit "other"-ish output.
		if tally != nil {
			tally.recordAssetType(string(effectiveAssetType))
		}
		cp.AssetType = "algorithm" // safest default
		cp.AlgorithmProperties = convertAlgorithmProperties(props)
	}

	return cp
}

// resolvePrimitive maps the internal primitive/AlgorithmPrimitive token to a
// CycloneDX 1.7 primitive enum value.
//
// Precedence:
//   - If types.CryptoProperties.AlgorithmPrimitive is set, first check the
//     canonicalTokenPrimitive map (handles "MD5", "AES-256-GCM", etc.).
//   - Then try primitiveMap (handles CycloneDX 1.7 enum strings like "hash").
//   - Unknown tokens fall back to PrimitiveOther (never passed through raw).
//   - If AlgorithmPrimitive is unset, use the legacy Primitive field via normalizePrimitive.
func resolvePrimitive(p *types.CryptoProperties) cyclonedx17.Primitive {
	primitive := normalizePrimitive(p.Primitive)
	if p.AlgorithmPrimitive != "" {
		// First check the canonical-token map (handles MD5, AES-256-GCM, etc.).
		// All keys are uppercase, so ToUpper normalizes any casing from the scanner.
		if cp, ok := canonicalTokenPrimitive[strings.ToUpper(p.AlgorithmPrimitive)]; ok {
			primitive = cp
		} else {
			// Unknown token — try as a primitive name, else default to "other".
			lower := strings.ToLower(strings.TrimSpace(p.AlgorithmPrimitive))
			if cp, ok := primitiveMap[lower]; ok {
				primitive = cp
			} else {
				primitive = cyclonedx17.PrimitiveOther
			}
		}
	}
	return primitive
}

// pqcParamPrefixes are PQC token prefixes (e.g. ML-KEM-768) whose suffix is the
// parameter set identifier (768).
var pqcParamPrefixes = []string{"ML-KEM-", "ML-DSA-", "SLH-DSA-", "KYBER-", "DILITHIUM-", "FALCON-", "SPHINCS-"}

// deriveParameterSet computes a CycloneDX parameterSetIdentifier — the parameter
// value alone (e.g. "256", "2048", "768"), since the component name already
// carries the algorithm family (decomposed style, per the CBOM schema reference).
// Returns "" if nothing reliable can be derived.
func deriveParameterSet(p *types.CryptoProperties) string {
	tok := strings.ToUpper(strings.TrimSpace(p.AlgorithmPrimitive))
	// 1. PQC tokens: the suffix after the family prefix is the parameter set.
	for _, pre := range pqcParamPrefixes {
		if strings.HasPrefix(tok, pre) {
			return strings.TrimPrefix(tok, pre)
		}
	}
	// 2. Classical parameterized token (e.g. AES-256-GCM): first numeric segment.
	for _, part := range strings.Split(tok, "-") {
		if _, err := strconv.Atoi(part); err == nil {
			return part
		}
	}
	// 3. Fall back to the explicit key size.
	if p.KeySize > 0 {
		return strconv.Itoa(p.KeySize)
	}
	return ""
}

// convertAlgorithmProperties maps types.CryptoProperties to CycloneDX AlgorithmProperties.
func convertAlgorithmProperties(p *types.CryptoProperties) *cyclonedx17.AlgorithmProperties {
	family := normalizeAlgorithmFamily(p.AlgorithmFamily)
	ap := &cyclonedx17.AlgorithmProperties{
		Primitive:                resolvePrimitive(p),
		AlgorithmFamily:          family,
		ParameterSetIdentifier:   deriveParameterSet(p),
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
		SubjectName:          p.SubjectName,
		IssuerName:           p.IssuerName,
		NotValidBefore:       p.NotValidBefore,
		NotValidAfter:        p.NotValidAfter,
		CertificateFormat:    p.CertificateFormat,
		CertificateExtension: strings.Join(p.CertificateExtensions, "; "),
	}
}

// algSlug normalizes an algorithm token into a content-addressed bom-ref slug.
func algSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

// certPublicKeyPrimitive maps a certificate public-key algorithm to a CycloneDX
// primitive. RSA cert keys are used for encryption/verification (pke); the EC /
// EdDSA / DSA families are signature primitives in this context.
func certPublicKeyPrimitive(pubAlgo string) cyclonedx17.Primitive {
	switch strings.ToUpper(pubAlgo) {
	case "RSA":
		return cyclonedx17.PrimitivePKE
	case "ECDSA", "ED25519", "DSA":
		return cyclonedx17.PrimitiveSignature
	default:
		return cyclonedx17.PrimitiveOther
	}
}

// syntheticAlgorithmComponent builds a deduplicated algorithm component (with
// quantum posture + migration properties) for a certificate's signature or
// public-key algorithm.
func syntheticAlgorithmComponent(ref, name, family string, primitive cyclonedx17.Primitive, keySize int) Component {
	info := quantum.GetInfo(family)
	ap := &cyclonedx17.AlgorithmProperties{
		Primitive:                primitive,
		AlgorithmFamily:          normalizeAlgorithmFamily(family),
		NistQuantumSecurityLevel: info.NistLevel,
	}
	if keySize > 0 {
		ap.ParameterSetIdentifier = strconv.Itoa(keySize)
		ap.ClassicalSecurityLevel = keySize
	}
	props := []Property{}
	if info.Status != "" && info.Status != types.QuantumNotApplicable && info.Status != types.QuantumUnknown {
		props = append(props, Property{Name: "quantumStatus", Value: string(info.Status)})
		props = appendQuantumMigrationProps(props, &types.CryptoProperties{
			QuantumStatus: info.Status, AlgorithmFamily: family, Primitive: string(primitive),
		})
	}
	return Component{
		Type:             "cryptographic-asset",
		BOMRef:           ref,
		Name:             name,
		CryptoProperties: &cyclonedx17.CryptoProperties{AssetType: "algorithm", AlgorithmProperties: ap},
		Properties:       props,
	}
}

// expandCertificateGraph wires a parsed certificate into a CycloneDX dependency
// graph: it emits a (shared) signature-algorithm component, a (shared)
// public-key-algorithm component, and a per-cert public-key material component,
// then sets the cert's refs and records dependency edges. No-op for certs that
// failed to parse (no public-key algorithm captured).
func expandCertificateGraph(cert *Component, f *types.Finding, acc *componentAccumulator) {
	p := &f.Properties
	if p.SubjectPublicKeyAlgorithm == "" || cert.CryptoProperties == nil || cert.CryptoProperties.CertificateProperties == nil {
		return
	}
	cp := cert.CryptoProperties.CertificateProperties
	var dependsOn []string

	// Signature-algorithm component (shared, content-addressed).
	if p.SignatureAlgorithm != "" {
		sigRef := "crypto/alg/" + algSlug(p.SignatureAlgorithm)
		sigFamily := sigFamilyFromPublicKey(p.SubjectPublicKeyAlgorithm)
		acc.addUnique(syntheticAlgorithmComponent(sigRef, p.SignatureAlgorithm, sigFamily, cyclonedx17.PrimitiveSignature, 0))
		cp.SignatureAlgorithmRef = sigRef
		dependsOn = append(dependsOn, sigRef)
	}

	// Public-key-algorithm component (shared) + per-cert key material component.
	pubAlgRef := "crypto/alg/" + algSlug(fmt.Sprintf("%s-%d", p.SubjectPublicKeyAlgorithm, p.SubjectPublicKeySize))
	acc.addUnique(syntheticAlgorithmComponent(
		pubAlgRef, p.SubjectPublicKeyAlgorithm, strings.ToLower(p.SubjectPublicKeyAlgorithm),
		certPublicKeyPrimitive(p.SubjectPublicKeyAlgorithm), p.SubjectPublicKeySize))

	keyRef := cert.BOMRef + "/subjectPublicKey"
	acc.add(Component{
		Type:   "cryptographic-asset",
		BOMRef: keyRef,
		Name:   fmt.Sprintf("%s public key", p.SubjectPublicKeyAlgorithm),
		CryptoProperties: &cyclonedx17.CryptoProperties{
			AssetType: "related-crypto-material",
			RelatedCryptoMaterialProperties: &cyclonedx17.RelatedCryptoMaterialProperties{
				Type:         cyclonedx17.RelatedCryptoMaterialTypePublicKey,
				Size:         p.SubjectPublicKeySize,
				AlgorithmRef: pubAlgRef,
			},
		},
	})
	cp.SubjectPublicKeyRef = keyRef
	dependsOn = append(dependsOn, keyRef)

	acc.dependsOn(cert.BOMRef, dependsOn...)
	acc.dependsOn(keyRef, pubAlgRef)
}

// sigFamilyFromPublicKey returns the quantum-relevant algorithm family for a
// certificate signature, derived from the signing key type.
func sigFamilyFromPublicKey(pubAlgo string) string {
	return strings.ToLower(pubAlgo)
}

// convertRelatedCryptoMaterialProperties maps types.CryptoProperties to CycloneDX RelatedCryptoMaterialProperties.
func convertRelatedCryptoMaterialProperties(p *types.CryptoProperties) *cyclonedx17.RelatedCryptoMaterialProperties {
	return &cyclonedx17.RelatedCryptoMaterialProperties{
		Type:  normalizeRelatedCryptoMaterialType(p.MaterialType),
		State: cyclonedx17.RelatedCryptoMaterialState(p.State),
		Size:  p.MaterialSize,
	}
}
