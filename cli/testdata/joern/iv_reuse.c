// Test fixture: static/constant IVs flowing into EVP_EncryptInit_ex.
// Reusing a static IV with the same key breaks CBC/CTR/GCM security.

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// Static IV as a global — should be detected.
static const unsigned char STATIC_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Helper that returns a fixed IV — inter-procedural flow.
static const unsigned char *get_fixed_iv(void) {
    static const unsigned char iv[] = "FixedIV-1234567";
    return iv;
}

// Direct hardcoded IV — should be detected.
int encrypt_static_iv_direct(const unsigned char *key,
                             const unsigned char *plaintext, int plaintext_len,
                             unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[] = "0000000000000000";  // hardcoded IV

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Global static IV — should be detected.
int encrypt_static_iv_global(const unsigned char *key,
                             const unsigned char *plaintext, int plaintext_len,
                             unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, STATIC_IV);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Inter-procedural: IV from helper function — should be detected.
int encrypt_static_iv_indirect(const unsigned char *key,
                               const unsigned char *plaintext, int plaintext_len,
                               unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned char *iv = get_fixed_iv();  // cross-function flow

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// All-zeros IV — should be detected.
int encrypt_zero_iv(const unsigned char *key,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    memset(iv, 0, sizeof(iv));  // all-zeros IV

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Older API: EVP_EncryptInit with static IV — should be detected.
int encrypt_legacy_static_iv(const unsigned char *key,
                             const unsigned char *plaintext, int plaintext_len,
                             unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[] = "LegacyStaticIV!";

    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Safe example: random IV — should NOT be detected.
int encrypt_random_iv(const unsigned char *key,
                      const unsigned char *plaintext, int plaintext_len,
                      unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));  // properly random IV

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}
