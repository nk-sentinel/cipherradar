use ring::digest;
use ring::aead;
use ring::agreement;
use ring::pbkdf2;
use ring::signature;
use rustls::ClientConfig;
use aes_gcm::{Aes256Gcm, Aes128Gcm, KeyInit};
use aes_gcm::aead::Aead as _;
use rsa::RsaPrivateKey;

// ring::digest - SHA-256
fn hash_sha256(data: &[u8]) {
    let _hash = digest::digest(&digest::SHA256, data);
}

// ring::digest - SHA-1 (broken)
fn hash_sha1(data: &[u8]) {
    let _hash = digest::digest(&digest::SHA1, data);
}

// ring::aead - AES-256-GCM
fn encrypt_aes_gcm(key_bytes: &[u8], nonce: &[u8], data: &[u8]) {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).unwrap();
    let key = aead::LessSafeKey::new(unbound_key);
}

// ring::aead - ChaCha20-Poly1305
fn encrypt_chacha(key_bytes: &[u8]) {
    let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes).unwrap();
}

// ring::agreement - X25519
fn key_agree_x25519() {
    let rng = ring::rand::SystemRandom::new();
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
}

// ring::agreement - ECDH P-256
fn key_agree_p256() {
    let rng = ring::rand::SystemRandom::new();
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
}

// ring::pbkdf2
fn derive_key(password: &[u8], salt: &[u8]) {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        salt,
        password,
        &mut key,
    );
}

// ring::signature - Ed25519
fn sign_ed25519(pkcs8_bytes: &[u8], message: &[u8]) {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();
    let _sig = key_pair.sign(message);
}

// ring::signature - ECDSA P256
fn sign_ecdsa(pkcs8_bytes: &[u8]) {
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_bytes,
        &ring::rand::SystemRandom::new(),
    ).unwrap();
}

// ring::signature - RSA
fn sign_rsa(pkcs8_bytes: &[u8]) {
    let key_pair = signature::RsaKeyPair::from_pkcs8(pkcs8_bytes).unwrap();
}

// rustls - TLS client config
fn rustls_client() {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
}

// rustls - cipher suites
static CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

// openssl crate - RSA
fn openssl_rsa() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
}

// openssl crate - hash
fn openssl_hash(data: &[u8]) {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()).unwrap();
}

// openssl crate - MD5 (broken)
fn openssl_md5(data: &[u8]) {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::md5()).unwrap();
}

// openssl crate - symmetric encryption
fn openssl_aes(key: &[u8], iv: &[u8], data: &[u8]) {
    let cipher = openssl::symm::Cipher::aes_256_cbc();
}

// openssl crate - DES (broken)
fn openssl_des(key: &[u8], iv: &[u8], data: &[u8]) {
    let cipher = openssl::symm::Cipher::des_cbc();
}

// RustCrypto aes-gcm crate - AES-256-GCM
fn rustcrypto_aes256_gcm(key_bytes: &[u8], nonce: &[u8], data: &[u8]) {
    let cipher = Aes256Gcm::new(key_bytes.into());
    let _ct = cipher.encrypt(nonce.into(), data).unwrap();
}

// RustCrypto aes-gcm crate - AES-128-GCM
fn rustcrypto_aes128_gcm(key_bytes: &[u8]) {
    let _cipher = Aes128Gcm::new(key_bytes.into());
}

// RustCrypto rsa crate - RSA keygen with literal bit size
fn rustcrypto_rsa_literal() {
    let mut rng = rand::thread_rng();
    let _priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}

// RustCrypto rsa crate - RSA keygen with const-propagated bit size
fn rustcrypto_rsa_constprop() {
    let bits = 4096;
    let mut rng = rand::thread_rng();
    let _priv = RsaPrivateKey::new(&mut rng, bits).unwrap();
}
