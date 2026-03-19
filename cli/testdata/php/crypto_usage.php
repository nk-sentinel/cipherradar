<?php
// Test fixture for PHP cryptographic API detection

// ---------------------------------------------------------------------------
// openssl_encrypt / openssl_decrypt
// ---------------------------------------------------------------------------

$data = "sensitive data";
$key = openssl_random_pseudo_bytes(32);
$iv = openssl_random_pseudo_bytes(16);

// AES-256-CBC encryption
$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);

// AES-256-CBC decryption
$decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);

// DES-ECB (weak — should be HIGH severity)
$des_encrypted = openssl_encrypt($data, 'DES-ECB', $key);

// AES-128-GCM
$tag = '';
$gcm_encrypted = openssl_encrypt($data, 'AES-128-GCM', $key, 0, $iv, $tag);

// Constant propagation: algorithm via variable
$method = 'AES-256-CBC';
$cp_encrypted = openssl_encrypt($data, $method, $key, 0, $iv);

// ---------------------------------------------------------------------------
// openssl_sign
// ---------------------------------------------------------------------------

$privateKey = openssl_pkey_get_private("file://private.pem");
openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);

// ---------------------------------------------------------------------------
// openssl_seal
// ---------------------------------------------------------------------------

$pubKeys = [openssl_pkey_get_public("file://public.pem")];
openssl_seal($data, $sealed, $ekeys, $pubKeys, 'AES-256-CBC');

// ---------------------------------------------------------------------------
// openssl_pkey_new (key generation)
// ---------------------------------------------------------------------------

// RSA key generation
$rsaConfig = [
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048,
];
$rsaKey = openssl_pkey_new($rsaConfig);

// EC key generation (inline config for direct detection)
$ecKey = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'prime256v1',
]);

// ---------------------------------------------------------------------------
// hash() / hash_hmac() / hash_pbkdf2()
// ---------------------------------------------------------------------------

// MD5 (broken — should be HIGH severity)
$md5 = hash('md5', $data);

// SHA-1 (broken — should be HIGH severity)
$sha1 = hash('sha1', $data);

// SHA-256
$sha256 = hash('sha256', $data);

// SHA-512
$sha512 = hash('sha512', $data);

// Constant propagation: hash algorithm via variable
$algo = 'sha256';
$cp_hash = hash($algo, $data);

// HMAC-SHA256
$hmac = hash_hmac('sha256', $data, $key);

// PBKDF2
$derived = hash_pbkdf2('sha256', 'password', 'salt', 100000, 32);

// PBKDF2 with low iterations (should be MEDIUM severity)
$weak_derived = hash_pbkdf2('sha256', 'password', 'salt', 1000, 32);

// ---------------------------------------------------------------------------
// password_hash / password_verify
// ---------------------------------------------------------------------------

$hashed = password_hash('secret', PASSWORD_BCRYPT);
$valid = password_verify('secret', $hashed);

$argon2 = password_hash('secret', PASSWORD_ARGON2ID);

// ---------------------------------------------------------------------------
// Sodium (NaCl/libsodium)
// ---------------------------------------------------------------------------

$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$sodiumKey = sodium_crypto_secretbox_keygen();

// secretbox (XSalsa20-Poly1305)
$ciphertext = sodium_crypto_secretbox($data, $nonce, $sodiumKey);

// box (X25519-XSalsa20-Poly1305)
$keypair = sodium_crypto_box_keypair();
$box_nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
$box_encrypted = sodium_crypto_box($data, $box_nonce, $keypair);

// sign (Ed25519)
$signKeypair = sodium_crypto_sign_keypair();
$signed = sodium_crypto_sign($data, $signKeypair);

// AEAD ChaCha20-Poly1305
$aead_nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
$aead_encrypted = sodium_crypto_aead_chacha20poly1305_encrypt($data, '', $aead_nonce, $sodiumKey);

// ---------------------------------------------------------------------------
// mcrypt (deprecated — should always be HIGH severity)
// ---------------------------------------------------------------------------

$mcrypt_encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
