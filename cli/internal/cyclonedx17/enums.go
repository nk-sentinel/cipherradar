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
	PrimitiveKEM          Primitive = "kem"
	PrimitivePKE          Primitive = "pke"
	PrimitiveXOF          Primitive = "xof"
	PrimitiveAE           Primitive = "ae"
	PrimitiveCombiner     Primitive = "combiner"
	PrimitiveKeyWrap      Primitive = "key-wrap"
	PrimitiveOther        Primitive = "other"
	PrimitiveUnknown      Primitive = "unknown"
)

// Mode represents an algorithm mode of operation as defined in CycloneDX 1.7.
type Mode string

const (
	ModeCBC     Mode = "cbc"
	ModeECB     Mode = "ecb"
	ModeCCM     Mode = "ccm"
	ModeGCM     Mode = "gcm"
	ModeCFB     Mode = "cfb"
	ModeOFB     Mode = "ofb"
	ModeCTR     Mode = "ctr"
	ModeOther   Mode = "other"
	ModeUnknown Mode = "unknown"
)

// Padding represents a padding scheme as defined in CycloneDX 1.7.
type Padding string

const (
	PaddingPKCS5    Padding = "pkcs5"
	PaddingPKCS7    Padding = "pkcs7"
	PaddingPKCS1v15 Padding = "pkcs1v15"
	PaddingOAEP     Padding = "oaep"
	PaddingRaw      Padding = "raw"
	PaddingOther    Padding = "other"
	PaddingUnknown  Padding = "unknown"
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
	CryptoFunctionKeyderive   CryptoFunction = "keyderive"
	CryptoFunctionSign        CryptoFunction = "sign"
	CryptoFunctionVerify      CryptoFunction = "verify"
	CryptoFunctionEncapsulate CryptoFunction = "encapsulate"
	CryptoFunctionDecapsulate CryptoFunction = "decapsulate"
	CryptoFunctionOther       CryptoFunction = "other"
	CryptoFunctionUnknown     CryptoFunction = "unknown"
)

// RelatedCryptoMaterialType represents the type of related cryptographic material
// as defined in CycloneDX 1.7.
type RelatedCryptoMaterialType string

const (
	RelatedCryptoMaterialTypePrivateKey           RelatedCryptoMaterialType = "private-key"
	RelatedCryptoMaterialTypePublicKey            RelatedCryptoMaterialType = "public-key"
	RelatedCryptoMaterialTypeSecretKey            RelatedCryptoMaterialType = "secret-key"
	RelatedCryptoMaterialTypeKey                  RelatedCryptoMaterialType = "key"
	RelatedCryptoMaterialTypeCiphertext           RelatedCryptoMaterialType = "ciphertext"
	RelatedCryptoMaterialTypeSignature            RelatedCryptoMaterialType = "signature"
	RelatedCryptoMaterialTypeDigest               RelatedCryptoMaterialType = "digest"
	RelatedCryptoMaterialTypeInitializationVector RelatedCryptoMaterialType = "initialization-vector"
	RelatedCryptoMaterialTypeNonce                RelatedCryptoMaterialType = "nonce"
	RelatedCryptoMaterialTypeSeed                 RelatedCryptoMaterialType = "seed"
	RelatedCryptoMaterialTypeSalt                 RelatedCryptoMaterialType = "salt"
	RelatedCryptoMaterialTypeSharedSecret         RelatedCryptoMaterialType = "shared-secret"
	RelatedCryptoMaterialTypeTag                  RelatedCryptoMaterialType = "tag"
	RelatedCryptoMaterialTypeAdditionalData       RelatedCryptoMaterialType = "additional-data"
	RelatedCryptoMaterialTypePassword             RelatedCryptoMaterialType = "password"
	RelatedCryptoMaterialTypeCredential           RelatedCryptoMaterialType = "credential"
	RelatedCryptoMaterialTypeToken                RelatedCryptoMaterialType = "token"
	RelatedCryptoMaterialTypeOther                RelatedCryptoMaterialType = "other"
	RelatedCryptoMaterialTypeUnknown              RelatedCryptoMaterialType = "unknown"
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
// Values must match the official CycloneDX 1.7 algorithmFamiliesEnum exactly.
type AlgorithmFamily string

const (
	AlgorithmFamilyAES             AlgorithmFamily = "AES"
	AlgorithmFamilyRSAES_OAEP     AlgorithmFamily = "RSAES-OAEP"
	AlgorithmFamilyRSAES_PKCS1    AlgorithmFamily = "RSAES-PKCS1"
	AlgorithmFamilyRSASSA_PKCS1   AlgorithmFamily = "RSASSA-PKCS1"
	AlgorithmFamilyRSASSA_PSS     AlgorithmFamily = "RSASSA-PSS"
	AlgorithmFamilyHMAC            AlgorithmFamily = "HMAC"
	AlgorithmFamilyDSA             AlgorithmFamily = "DSA"
	AlgorithmFamilyFFDH            AlgorithmFamily = "FFDH"
	AlgorithmFamilyECDSA           AlgorithmFamily = "ECDSA"
	AlgorithmFamilyECDH            AlgorithmFamily = "ECDH"
	AlgorithmFamilyECIES           AlgorithmFamily = "ECIES"
	AlgorithmFamilyEdDSA           AlgorithmFamily = "EdDSA"
	AlgorithmFamilyDES             AlgorithmFamily = "DES"
	AlgorithmFamily3DES            AlgorithmFamily = "3DES"
	AlgorithmFamilyBlowfish        AlgorithmFamily = "Blowfish"
	AlgorithmFamilyChaCha          AlgorithmFamily = "ChaCha"
	AlgorithmFamilyChaCha20        AlgorithmFamily = "ChaCha20"
	AlgorithmFamilyPoly1305        AlgorithmFamily = "Poly1305"
	AlgorithmFamilyCAMELLIA        AlgorithmFamily = "CAMELLIA"
	AlgorithmFamilyARIA            AlgorithmFamily = "ARIA"
	AlgorithmFamilySM2             AlgorithmFamily = "SM2"
	AlgorithmFamilySM3             AlgorithmFamily = "SM3"
	AlgorithmFamilySM4             AlgorithmFamily = "SM4"
	AlgorithmFamilyMLKEM           AlgorithmFamily = "ML-KEM"
	AlgorithmFamilyMLDSA           AlgorithmFamily = "ML-DSA"
	AlgorithmFamilySLHDSA          AlgorithmFamily = "SLH-DSA"
	AlgorithmFamilyBIKE            AlgorithmFamily = "BIKE"
	AlgorithmFamilyHQC             AlgorithmFamily = "HQC"
	AlgorithmFamilyMD2             AlgorithmFamily = "MD2"
	AlgorithmFamilyMD4             AlgorithmFamily = "MD4"
	AlgorithmFamilyMD5             AlgorithmFamily = "MD5"
	AlgorithmFamilySHA1            AlgorithmFamily = "SHA-1"
	AlgorithmFamilySHA2            AlgorithmFamily = "SHA-2"
	AlgorithmFamilySHA3            AlgorithmFamily = "SHA-3"
	AlgorithmFamilyBLAKE2          AlgorithmFamily = "BLAKE2"
	AlgorithmFamilyBLAKE3          AlgorithmFamily = "BLAKE3"
	AlgorithmFamilyRC2             AlgorithmFamily = "RC2"
	AlgorithmFamilyRC4             AlgorithmFamily = "RC4"
	AlgorithmFamilyRC5             AlgorithmFamily = "RC5"
	AlgorithmFamilyRC6             AlgorithmFamily = "RC6"
	AlgorithmFamilyIDEA            AlgorithmFamily = "IDEA"
	AlgorithmFamilyCAST5           AlgorithmFamily = "CAST5"
	AlgorithmFamilyCAST6           AlgorithmFamily = "CAST6"
	AlgorithmFamilyTwofish         AlgorithmFamily = "Twofish"
	AlgorithmFamilySerpent         AlgorithmFamily = "Serpent"
	AlgorithmFamilySEED            AlgorithmFamily = "SEED"
	AlgorithmFamilyRIPEMD          AlgorithmFamily = "RIPEMD"
	AlgorithmFamilyWhirlpool       AlgorithmFamily = "Whirlpool"
	AlgorithmFamilyCMACFamily      AlgorithmFamily = "CMAC"
	AlgorithmFamilyKMAC            AlgorithmFamily = "KMAC"
	AlgorithmFamilyHKDF            AlgorithmFamily = "HKDF"
	AlgorithmFamilyPBKDF1          AlgorithmFamily = "PBKDF1"
	AlgorithmFamilyPBKDF2          AlgorithmFamily = "PBKDF2"
	AlgorithmFamilyPBES1           AlgorithmFamily = "PBES1"
	AlgorithmFamilyPBES2           AlgorithmFamily = "PBES2"
	AlgorithmFamilyPBMAC1          AlgorithmFamily = "PBMAC1"
	AlgorithmFamilySP800_108       AlgorithmFamily = "SP800-108"
	AlgorithmFamilyScrypt          AlgorithmFamily = "scrypt"
	AlgorithmFamilyBcrypt          AlgorithmFamily = "bcrypt"
	AlgorithmFamilyArgon2          AlgorithmFamily = "Argon2"
	AlgorithmFamilyElGamal         AlgorithmFamily = "ElGamal"
	AlgorithmFamilyGOST            AlgorithmFamily = "GOST"
	AlgorithmFamilyLMS             AlgorithmFamily = "LMS"
	AlgorithmFamilyXMSS            AlgorithmFamily = "XMSS"
	AlgorithmFamilyHPKE            AlgorithmFamily = "HPKE"
	AlgorithmFamilyBLS             AlgorithmFamily = "BLS"
	AlgorithmFamilySipHash         AlgorithmFamily = "SipHash"
	AlgorithmFamilyUMAC            AlgorithmFamily = "UMAC"
	AlgorithmFamilySkipjack        AlgorithmFamily = "Skipjack"
	AlgorithmFamilyFortuna         AlgorithmFamily = "Fortuna"
	AlgorithmFamilyCTR_DRBG        AlgorithmFamily = "CTR_DRBG"
	AlgorithmFamilyHMAC_DRBG       AlgorithmFamily = "HMAC_DRBG"
	AlgorithmFamilyHash_DRBG       AlgorithmFamily = "Hash_DRBG"
	AlgorithmFamilySalsa20         AlgorithmFamily = "Salsa20"
	AlgorithmFamilyRABBIT          AlgorithmFamily = "RABBIT"
	AlgorithmFamilyHC              AlgorithmFamily = "HC"
	AlgorithmFamilySNOW3G          AlgorithmFamily = "SNOW3G"
	AlgorithmFamilyZUC             AlgorithmFamily = "ZUC"
	AlgorithmFamilyCMEA            AlgorithmFamily = "CMEA"
	AlgorithmFamilyA5_1            AlgorithmFamily = "A5/1"
	AlgorithmFamilyA5_2            AlgorithmFamily = "A5/2"
	AlgorithmFamily3GPP_XOR        AlgorithmFamily = "3GPP-XOR"
	AlgorithmFamilyMILENAGE        AlgorithmFamily = "MILENAGE"
	AlgorithmFamilyTUAK            AlgorithmFamily = "TUAK"
	AlgorithmFamilyAscon           AlgorithmFamily = "Ascon"
	AlgorithmFamilySM9             AlgorithmFamily = "SM9"
	AlgorithmFamilyMQV             AlgorithmFamily = "MQV"
	AlgorithmFamilyOPAQUE          AlgorithmFamily = "OPAQUE"
	AlgorithmFamilySPAKE2          AlgorithmFamily = "SPAKE2"
	AlgorithmFamilySPAKE2PLUS      AlgorithmFamily = "SPAKE2PLUS"
	AlgorithmFamilySRP             AlgorithmFamily = "SRP"
	AlgorithmFamilyJPAKE           AlgorithmFamily = "J-PAKE"
	AlgorithmFamilyX3DH            AlgorithmFamily = "X3DH"
	AlgorithmFamilyEAP_AKA         AlgorithmFamily = "EAP-AKA"
	AlgorithmFamilyEAP_AKA_PRIME   AlgorithmFamily = "EAP-AKA-PRIME"
	AlgorithmFamily5G_AKA          AlgorithmFamily = "5G-AKA"
	AlgorithmFamilyIKE_PRF         AlgorithmFamily = "IKE-PRF"
)
