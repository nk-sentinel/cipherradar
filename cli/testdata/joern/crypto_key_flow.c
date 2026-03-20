// Test fixture: hardcoded key material flowing into OpenSSL crypto APIs.
// Expected findings: hardcoded AES key passed to EVP_EncryptInit_ex and AES_set_encrypt_key.

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>

// Hardcoded key as a global constant — should be detected.
static const unsigned char HARDCODED_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Helper function that returns a hardcoded key — inter-procedural flow.
static const unsigned char *get_encryption_key(void) {
    static const unsigned char key[] = "ThisIsASecretKey";
    return key;
}

// Direct hardcoded key into EVP_EncryptInit_ex — should be detected.
int encrypt_data_direct(const unsigned char *plaintext, int plaintext_len,
                        unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[] = "0123456789abcdef";  // hardcoded key
    unsigned char iv[] = "abcdef0123456789";

    // Hardcoded key flows directly to EVP_EncryptInit_ex
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Inter-procedural: key from helper function into EVP_EncryptInit_ex.
int encrypt_data_indirect(const unsigned char *plaintext, int plaintext_len,
                          unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned char *key = get_encryption_key();  // cross-function flow
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));  // IV is random (good)

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Hardcoded key into AES_set_encrypt_key — should be detected.
int encrypt_with_aes_api(const unsigned char *input, unsigned char *output) {
    AES_KEY aes_key;
    unsigned char key[] = "HardcodedAESKey!";  // hardcoded

    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(input, output, &aes_key);
    return 0;
}

// Global hardcoded key used across functions — should be detected.
int encrypt_with_global_key(const unsigned char *plaintext, int len,
                            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, HARDCODED_KEY, iv);

    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);

    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

// Safe example: key from proper KDF — should NOT be detected.
int encrypt_data_safe(const unsigned char *plaintext, int plaintext_len,
                      const unsigned char *password, int password_len,
                      unsigned char *ciphertext) {
    unsigned char key[32];
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    // Key derived from password — not hardcoded
    PKCS5_PBKDF2_HMAC(password, password_len, salt, sizeof(salt),
                       100000, EVP_sha256(), sizeof(key), key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return len;
}
