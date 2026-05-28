// Fixture for OpenSSL classic asymmetric API detection (issue #34, Tier-1 gap fill).
// Covers DSA, DH, EC, ECDSA, and ECDH — the quantum-vulnerable families whose
// OpenSSL function names unambiguously identify the algorithm.
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>

void make_dsa() {
    DSA *d = DSA_new();
    DSA_generate_parameters_ex(d, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(d);
}

void make_dh() {
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, 2, NULL);
    DH_generate_key(dh);
}

EC_KEY *make_ec() {
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}

int sign_ecdsa(const unsigned char *digest, int len, unsigned char *sig,
               unsigned int *siglen, EC_KEY *key) {
    return ECDSA_sign(0, digest, len, sig, siglen, key);
}

int agree_ecdh(unsigned char *out, size_t outlen, const EC_POINT *pub, EC_KEY *key) {
    return ECDH_compute_key(out, outlen, pub, key, NULL);
}
