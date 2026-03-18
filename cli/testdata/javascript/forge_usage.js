const forge = require('node-forge');

// BAD: MD5
const md5 = forge.md.md5.create();
md5.update('data');

// GOOD: SHA-256
const sha256 = forge.md.sha256.create();
sha256.update('data');

// AES-CBC
const cipher = forge.cipher.createCipher('AES-CBC', key);

// RSA-2048
const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
