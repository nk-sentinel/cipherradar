#include <botan/gost_3410.h>
#include <openssl/evp.h>

// GOST R 34.10 signature via Botan (quantum-vulnerable)
// EXPECTED: GOST3410 | signature | | info | quantum-vulnerable
void sign() {
    Botan::GOST_3410_PrivateKey key;
}

// GOST R 34.11 hash via OpenSSL gost engine
// EXPECTED: GOST3411 | hash | | info |
void hash() {
    const EVP_MD *md = EVP_get_digestbyname("md_gost12_256");
}
