import CryptoKit
import CommonCrypto
import Security

// ---------------------------------------------------------------------------
// CryptoKit: AES-GCM
// ---------------------------------------------------------------------------

let symmetricKey = SymmetricKey(size: .bits256)
let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey)
let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)

// ---------------------------------------------------------------------------
// CryptoKit: ChaChaPoly
// ---------------------------------------------------------------------------

let chachaSealed = try ChaChaPoly.seal(plaintext, using: symmetricKey)
let chachaDecrypted = try ChaChaPoly.open(chachaSealed, using: symmetricKey)

// ---------------------------------------------------------------------------
// CryptoKit: Hashes
// ---------------------------------------------------------------------------

let sha256Digest = SHA256.hash(data: data)
let sha384Digest = SHA384.hash(data: data)
let sha512Digest = SHA512.hash(data: data)

// ---------------------------------------------------------------------------
// CryptoKit: HMAC
// ---------------------------------------------------------------------------

let hmac256 = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)

// ---------------------------------------------------------------------------
// CryptoKit: Elliptic Curve Signing
// ---------------------------------------------------------------------------

let p256Key = P256.Signing.PrivateKey()
let p384Key = P384.Signing.PrivateKey()
let p521Key = P521.Signing.PrivateKey()
let ed25519Key = Curve25519.Signing.PrivateKey()

// ---------------------------------------------------------------------------
// CryptoKit: Key Agreement
// ---------------------------------------------------------------------------

let kaKey = Curve25519.KeyAgreement.PrivateKey()

// ---------------------------------------------------------------------------
// CommonCrypto: CCCrypt
// ---------------------------------------------------------------------------

var status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), 0, key, keyLength, iv, data, dataLength, buffer, bufferSize, &numBytesEncrypted)
var desStatus = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(kCCOptionECBMode), key, keyLength, nil, data, dataLength, buffer, bufferSize, &numBytesEncrypted)
var rc4Status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmRC4), CCOptions(0), key, keyLength, nil, data, dataLength, buffer, bufferSize, &numBytesEncrypted)
var tdesStatus = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithm3DES), 0, key, keyLength, iv, data, dataLength, buffer, bufferSize, &numBytesEncrypted)

// ---------------------------------------------------------------------------
// CommonCrypto: CCHmac
// ---------------------------------------------------------------------------

CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, keyLength, data, dataLength, macOut)

// ---------------------------------------------------------------------------
// CommonCrypto: Hash functions
// ---------------------------------------------------------------------------

CC_SHA256(data, CC_LONG(data.count), &digest)
CC_SHA1(data, CC_LONG(data.count), &digest)
CC_MD5(data, CC_LONG(data.count), &digest)

// ---------------------------------------------------------------------------
// CommonCrypto: PBKDF
// ---------------------------------------------------------------------------

CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, passwordLen, salt, saltLen, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 10000, derivedKey, derivedKeyLen)

// ---------------------------------------------------------------------------
// Security framework
// ---------------------------------------------------------------------------

let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
let certificate = SecCertificateCreateWithData(nil, certData as CFData)

// TLS via Network.framework
let tlsOptions = NWProtocolTLS.Options()
