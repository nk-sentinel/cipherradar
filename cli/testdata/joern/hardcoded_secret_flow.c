// Test fixture: hardcoded secrets flowing into HMAC, EVP_DigestSignInit,
// and password parameters across function boundaries.

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

// Hardcoded HMAC secret — should be detected.
static const char *HMAC_SECRET = "my-super-secret-hmac-key-12345";

// Helper that returns a hardcoded password — inter-procedural flow.
static const char *get_db_password(void) {
    return "P@ssw0rd!2024SecretDB";
}

// Direct hardcoded secret into HMAC() — should be detected.
unsigned char *compute_hmac_direct(const unsigned char *data, int data_len,
                                   unsigned int *hmac_len) {
    const char *secret = "hardcoded-hmac-secret-key";
    return HMAC(EVP_sha256(), secret, strlen(secret),
                data, data_len, NULL, hmac_len);
}

// Inter-procedural: global secret into HMAC() — should be detected.
unsigned char *compute_hmac_global(const unsigned char *data, int data_len,
                                   unsigned int *hmac_len) {
    return HMAC(EVP_sha256(), HMAC_SECRET, strlen(HMAC_SECRET),
                data, data_len, NULL, hmac_len);
}

// Hardcoded password into PKCS5_PBKDF2_HMAC — should be detected.
int derive_key_hardcoded(unsigned char *key_out, int key_len) {
    const char *password = "HardcodedPassword123!";
    unsigned char salt[16] = {0};

    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                              salt, sizeof(salt),
                              10000, EVP_sha256(),
                              key_len, key_out);
}

// Inter-procedural: password from helper into PKCS5_PBKDF2_HMAC.
int derive_key_indirect(unsigned char *key_out, int key_len) {
    const char *password = get_db_password();  // cross-function flow
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                              salt, sizeof(salt),
                              100000, EVP_sha256(),
                              key_len, key_out);
}

// Hardcoded signing key material — should be detected.
int sign_data_hardcoded(const unsigned char *data, size_t data_len,
                        unsigned char *sig, size_t *sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY *pkey = NULL;

    // Loading key from hardcoded PEM string (simplified).
    const char *pem_key = "-----BEGIN PRIVATE KEY-----\n"
                          "MIIEvgIBADANBgkqhkiG9w0BAQEFAAS...\n"
                          "-----END PRIVATE KEY-----\n";

    BIO *bio = BIO_new_mem_buf(pem_key, -1);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, data, data_len);
    EVP_DigestSignFinal(mdctx, sig, sig_len);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return 0;
}

// Custom auth function with hardcoded password — should be detected.
int authenticate_user(const char *username) {
    const char *admin_password = "admin123!@#secret";

    // Simulated password check
    if (strcmp(username, "admin") == 0) {
        // hardcoded password flows into authentication logic
        return check_password(username, admin_password);
    }
    return 0;
}

int check_password(const char *user, const char *passwd) {
    // Placeholder authentication
    return (passwd != NULL) ? 1 : 0;
}

// Safe example: HMAC with externally provided key — should NOT be detected.
unsigned char *compute_hmac_safe(const unsigned char *key, int key_len,
                                 const unsigned char *data, int data_len,
                                 unsigned int *hmac_len) {
    return HMAC(EVP_sha256(), key, key_len,
                data, data_len, NULL, hmac_len);
}
