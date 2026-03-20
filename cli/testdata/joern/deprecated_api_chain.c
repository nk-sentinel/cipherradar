// Test fixture: deprecated OpenSSL API usage in call chains.
// DES_*, RC4, MD5_Init, SHA1_Init are all deprecated/broken.

#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/blowfish.h>
#include <string.h>

// DES encryption — should be detected (critical).
void encrypt_des(const unsigned char *input, unsigned char *output,
                 DES_key_schedule *ks) {
    DES_ecb_encrypt((const_DES_cblock *)input, (DES_cblock *)output,
                    ks, DES_ENCRYPT);
}

// DES key setup — should be detected (critical).
int setup_des_key(const unsigned char *key_data, DES_key_schedule *ks) {
    DES_cblock key;
    memcpy(key, key_data, 8);
    DES_set_key_checked(&key, ks);
    return 0;
}

// Triple-DES still uses DES_* APIs — should be detected.
void encrypt_3des(const unsigned char *input, unsigned char *output,
                  DES_key_schedule *ks1, DES_key_schedule *ks2,
                  DES_key_schedule *ks3) {
    DES_ecb3_encrypt((const_DES_cblock *)input, (DES_cblock *)output,
                     ks1, ks2, ks3, DES_ENCRYPT);
}

// MD5 hash — should be detected (high).
void compute_md5(const unsigned char *data, size_t len,
                 unsigned char *digest) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(digest, &ctx);
}

// SHA1 hash — should be detected (high).
void compute_sha1(const unsigned char *data, size_t len,
                  unsigned char *digest) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(digest, &ctx);
}

// RC4 encryption — should be detected (critical).
void encrypt_rc4(const unsigned char *key, int key_len,
                 unsigned char *data, int data_len) {
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, key_len, key);
    RC4(&rc4_key, data_len, data, data);
}

// EVP wrappers for deprecated algorithms — should be detected.
void hash_md5_evp(const unsigned char *data, size_t len,
                  unsigned char *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
}

void hash_sha1_evp(const unsigned char *data, size_t len,
                   unsigned char *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Blowfish — should be detected (medium).
void encrypt_blowfish(const unsigned char *key, int key_len,
                      unsigned char *data) {
    BF_KEY bf_key;
    BF_set_key(&bf_key, key_len, key);
    BF_ecb_encrypt(data, data, &bf_key, BF_ENCRYPT);
}

// Call chain: function calls deprecated API indirectly.
void process_legacy_data(const unsigned char *data, size_t len) {
    unsigned char md5_hash[16];
    unsigned char sha1_hash[20];

    // Both deprecated — should trace call chain.
    compute_md5(data, len, md5_hash);
    compute_sha1(data, len, sha1_hash);
}

// Safe example: using modern EVP_sha256 — should NOT be detected.
void hash_sha256_safe(const unsigned char *data, size_t len,
                      unsigned char *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Safe example: AES-256-GCM — should NOT be detected.
int encrypt_aes256_gcm_safe(const unsigned char *key, const unsigned char *iv,
                            const unsigned char *plaintext, int plaintext_len,
                            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}
