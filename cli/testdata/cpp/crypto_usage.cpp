#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sodium.h>

// OpenSSL EVP encryption
void evp_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
}

// OpenSSL EVP digest
void evp_digest(const unsigned char *data, size_t len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
}

// OpenSSL SHA-256
void sha256_hash(const unsigned char *data, size_t len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
}

// OpenSSL MD5 (broken)
void md5_hash(const unsigned char *data, size_t len) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(data, len, hash);
}

// OpenSSL SHA-1 (broken)
void sha1_hash(const unsigned char *data, size_t len) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, len, hash);
}

// OpenSSL RSA key generation
void rsa_keygen() {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
}

// OpenSSL AES key setup
void aes_encrypt(const unsigned char *key) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);
}

// OpenSSL HMAC
void hmac_sha256(const unsigned char *key, const unsigned char *data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(EVP_sha256(), key, 32, data, 64, result, &len);
}

// OpenSSL PBKDF2 key derivation
void pbkdf2_derive(const char *pass, const unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC(pass, -1, salt, 16, 100000, EVP_sha256(), 32, out);
}

// OpenSSL PBKDF2 with SHA-1
void pbkdf2_derive_sha1(const char *pass, const unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC_SHA1(pass, -1, salt, 16, 100000, 32, out);
}

// OpenSSL PEM private key reading
void read_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
}

// OpenSSL SSL context with TLS method
void setup_tls() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}

// OpenSSL SSL with deprecated TLS 1.0
void setup_bad_tls() {
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
}

// libsodium secretbox
void sodium_secretbox_usage(const unsigned char *msg, const unsigned char *key) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[128];
    crypto_secretbox_easy(ciphertext, msg, 64, nonce, key);
}

// libsodium box (public-key encryption)
void sodium_box_usage() {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
}

// libsodium sign
void sodium_sign_usage() {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
}

// libsodium AEAD
void sodium_aead_usage(const unsigned char *msg, const unsigned char *key) {
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[128];
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &clen, msg, 64, NULL, 0, NULL, nonce, key);
}

// libsodium password hashing
void sodium_pwhash_usage(const char *password) {
    char hashed[crypto_pwhash_STRBYTES];
    crypto_pwhash_str(hashed, password, strlen(password),
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

// DES (broken)
void des_usage(const unsigned char *key) {
    DES_key_schedule ks;
    DES_set_key(key, &ks);
}

// RC4 (broken)
void rc4_usage(const unsigned char *key) {
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, 16, key);
}
