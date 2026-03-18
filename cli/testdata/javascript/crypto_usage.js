const crypto = require('crypto');

// BAD: MD5
const md5Hash = crypto.createHash('md5').update('data').digest('hex');

// GOOD: SHA-256
const sha256Hash = crypto.createHash('sha256').update('data').digest('hex');

// BAD: DES
const desCipher = crypto.createCipher('des', 'password');

// GOOD: AES-256-GCM
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const aesCipher = crypto.createCipheriv('aes-256-gcm', key, iv);

// QUANTUM-VULNERABLE: RSA-2048
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// HMAC
const hmac = crypto.createHmac('sha256', 'secret');

// PBKDF2
crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');

// ECDH
const ecdh = crypto.createECDH('secp256k1');
