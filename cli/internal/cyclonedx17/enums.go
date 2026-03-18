package cyclonedx17

// Primitive represents a cryptographic primitive type as defined in CycloneDX 1.7.
type Primitive string

const (
	PrimitiveDRBG         Primitive = "drbg"
	PrimitiveBlockCipher  Primitive = "block-cipher"
	PrimitiveStreamCipher Primitive = "stream-cipher"
	PrimitiveHash         Primitive = "hash"
	PrimitiveMAC          Primitive = "mac"
	PrimitiveSignature    Primitive = "signature"
	PrimitiveKDF          Primitive = "kdf"
	PrimitiveKeyAgree     Primitive = "key-agree"
	PrimitivePKE          Primitive = "pke"
	PrimitiveXOF          Primitive = "xof"
	PrimitiveAE           Primitive = "ae"
	PrimitiveOther        Primitive = "other"
	PrimitiveUnknown      Primitive = "unknown"
)

// Mode represents an algorithm mode of operation as defined in CycloneDX 1.7.
type Mode string

const (
	ModeCBC     Mode = "cbc"
	ModeECB     Mode = "ecb"
	ModeCTR     Mode = "ctr"
	ModeGCM     Mode = "gcm"
	ModeCCM     Mode = "ccm"
	ModeOFB     Mode = "ofb"
	ModeCFB     Mode = "cfb"
	ModeOther   Mode = "other"
	ModeUnknown Mode = "unknown"
)

// Padding represents a padding scheme as defined in CycloneDX 1.7.
type Padding string

const (
	PaddingPKCS5   Padding = "pkcs5"
	PaddingPKCS7   Padding = "pkcs7"
	PaddingOAEP    Padding = "oaep"
	PaddingRaw     Padding = "raw"
	PaddingOther   Padding = "other"
	PaddingUnknown Padding = "unknown"
)

// CryptoFunction represents a cryptographic function as defined in CycloneDX 1.7.
type CryptoFunction string

const (
	CryptoFunctionGenerate    CryptoFunction = "generate"
	CryptoFunctionKeygen      CryptoFunction = "keygen"
	CryptoFunctionEncrypt     CryptoFunction = "encrypt"
	CryptoFunctionDecrypt     CryptoFunction = "decrypt"
	CryptoFunctionDigest      CryptoFunction = "digest"
	CryptoFunctionTag         CryptoFunction = "tag"
	CryptoFunctionSign        CryptoFunction = "sign"
	CryptoFunctionVerify      CryptoFunction = "verify"
	CryptoFunctionDerive      CryptoFunction = "derive"
	CryptoFunctionEncapsulate CryptoFunction = "encapsulate"
	CryptoFunctionDecapsulate CryptoFunction = "decapsulate"
	CryptoFunctionOther       CryptoFunction = "other"
	CryptoFunctionUnknown     CryptoFunction = "unknown"
)

// RelatedCryptoMaterialType represents the type of related cryptographic material
// as defined in CycloneDX 1.7.
type RelatedCryptoMaterialType string

const (
	RelatedCryptoMaterialTypePrivateKey      RelatedCryptoMaterialType = "private-key"
	RelatedCryptoMaterialTypePublicKey       RelatedCryptoMaterialType = "public-key"
	RelatedCryptoMaterialTypeSecretKey       RelatedCryptoMaterialType = "secret-key"
	RelatedCryptoMaterialTypeKey             RelatedCryptoMaterialType = "key"
	RelatedCryptoMaterialTypeCiphertext      RelatedCryptoMaterialType = "ciphertext"
	RelatedCryptoMaterialTypeSignature       RelatedCryptoMaterialType = "signature"
	RelatedCryptoMaterialTypeDigest          RelatedCryptoMaterialType = "digest"
	RelatedCryptoMaterialTypeIV              RelatedCryptoMaterialType = "iv"
	RelatedCryptoMaterialTypeNonce           RelatedCryptoMaterialType = "nonce"
	RelatedCryptoMaterialTypeSeed            RelatedCryptoMaterialType = "seed"
	RelatedCryptoMaterialTypeSalt            RelatedCryptoMaterialType = "salt"
	RelatedCryptoMaterialTypeSharedSecret    RelatedCryptoMaterialType = "shared-secret"
	RelatedCryptoMaterialTypeTag             RelatedCryptoMaterialType = "tag"
	RelatedCryptoMaterialTypeAdditionalData  RelatedCryptoMaterialType = "additional-data"
	RelatedCryptoMaterialTypePassword        RelatedCryptoMaterialType = "password"
	RelatedCryptoMaterialTypeCredential      RelatedCryptoMaterialType = "credential"
	RelatedCryptoMaterialTypeToken           RelatedCryptoMaterialType = "token"
	RelatedCryptoMaterialTypeOther           RelatedCryptoMaterialType = "other"
	RelatedCryptoMaterialTypeUnknown         RelatedCryptoMaterialType = "unknown"
)

// RelatedCryptoMaterialState represents the lifecycle state of cryptographic material
// as defined in CycloneDX 1.7.
type RelatedCryptoMaterialState string

const (
	RelatedCryptoMaterialStatePreActivation RelatedCryptoMaterialState = "pre-activation"
	RelatedCryptoMaterialStateActive        RelatedCryptoMaterialState = "active"
	RelatedCryptoMaterialStateSuspended     RelatedCryptoMaterialState = "suspended"
	RelatedCryptoMaterialStateDeactivated   RelatedCryptoMaterialState = "deactivated"
	RelatedCryptoMaterialStateCompromised   RelatedCryptoMaterialState = "compromised"
	RelatedCryptoMaterialStateDestroyed     RelatedCryptoMaterialState = "destroyed"
)

// AlgorithmFamily represents an algorithm family as defined in CycloneDX 1.7.
type AlgorithmFamily string

const (
	AlgorithmFamilyAES             AlgorithmFamily = "aes"
	AlgorithmFamilyRSA             AlgorithmFamily = "rsa"
	AlgorithmFamilyEC              AlgorithmFamily = "ec"
	AlgorithmFamilySHA             AlgorithmFamily = "sha"
	AlgorithmFamilyHMAC            AlgorithmFamily = "hmac"
	AlgorithmFamilyDSA             AlgorithmFamily = "dsa"
	AlgorithmFamilyDH              AlgorithmFamily = "dh"
	AlgorithmFamilyECDSA           AlgorithmFamily = "ecdsa"
	AlgorithmFamilyECDH            AlgorithmFamily = "ecdh"
	AlgorithmFamilyEd25519         AlgorithmFamily = "ed25519"
	AlgorithmFamilyEd448           AlgorithmFamily = "ed448"
	AlgorithmFamilyX25519          AlgorithmFamily = "x25519"
	AlgorithmFamilyX448            AlgorithmFamily = "x448"
	AlgorithmFamilyDES             AlgorithmFamily = "des"
	AlgorithmFamily3DES            AlgorithmFamily = "3des"
	AlgorithmFamilyBlowfish        AlgorithmFamily = "blowfish"
	AlgorithmFamilyChaCha20        AlgorithmFamily = "chacha20"
	AlgorithmFamilyPoly1305        AlgorithmFamily = "poly1305"
	AlgorithmFamilyCamellia        AlgorithmFamily = "camellia"
	AlgorithmFamilyARIA            AlgorithmFamily = "aria"
	AlgorithmFamilySM2             AlgorithmFamily = "sm2"
	AlgorithmFamilySM3             AlgorithmFamily = "sm3"
	AlgorithmFamilySM4             AlgorithmFamily = "sm4"
	AlgorithmFamilyMLKEM           AlgorithmFamily = "ml-kem"
	AlgorithmFamilyMLDSA           AlgorithmFamily = "ml-dsa"
	AlgorithmFamilySLHDSA          AlgorithmFamily = "slh-dsa"
	AlgorithmFamilyFalcon          AlgorithmFamily = "falcon"
	AlgorithmFamilyBIKE            AlgorithmFamily = "bike"
	AlgorithmFamilyHQC             AlgorithmFamily = "hqc"
	AlgorithmFamilyClassicMcEliece AlgorithmFamily = "classic-mceliece"
	AlgorithmFamilyFrodoKEM        AlgorithmFamily = "frodokem"
	AlgorithmFamilyNTRU            AlgorithmFamily = "ntru"
	AlgorithmFamilySaber           AlgorithmFamily = "saber"
	AlgorithmFamilyKyber           AlgorithmFamily = "kyber"
	AlgorithmFamilyDilithium       AlgorithmFamily = "dilithium"
	AlgorithmFamilySPHINCS         AlgorithmFamily = "sphincs"
	AlgorithmFamilyMD5             AlgorithmFamily = "md5"
	AlgorithmFamilySHA1            AlgorithmFamily = "sha1"
	AlgorithmFamilySHA2            AlgorithmFamily = "sha2"
	AlgorithmFamilySHA3            AlgorithmFamily = "sha3"
	AlgorithmFamilyBLAKE2          AlgorithmFamily = "blake2"
	AlgorithmFamilyBLAKE3          AlgorithmFamily = "blake3"
	AlgorithmFamilyRC4             AlgorithmFamily = "rc4"
	AlgorithmFamilyIDEA            AlgorithmFamily = "idea"
	AlgorithmFamilyCAST            AlgorithmFamily = "cast"
	AlgorithmFamilyTwofish         AlgorithmFamily = "twofish"
	AlgorithmFamilySerpent         AlgorithmFamily = "serpent"
	AlgorithmFamilyScrypt          AlgorithmFamily = "scrypt"
	AlgorithmFamilyBcrypt          AlgorithmFamily = "bcrypt"
	AlgorithmFamilyArgon2          AlgorithmFamily = "argon2"
	AlgorithmFamilyPBKDF2          AlgorithmFamily = "pbkdf2"
	AlgorithmFamilyHKDF            AlgorithmFamily = "hkdf"
	AlgorithmFamilyOther           AlgorithmFamily = "other"
	AlgorithmFamilyUnknown         AlgorithmFamily = "unknown"
)
