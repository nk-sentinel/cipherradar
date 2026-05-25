/*
 * Hash algorithm constants in compiled binaries.
 *
 * Every cryptographic hash defined by NIST has a fixed initial state
 * (IV) and a fixed round-constants table. Those values are baked into
 * any conforming implementation, statically linked or otherwise. The
 * byte patterns in this file are the same across openssl, mbedtls,
 * go's crypto stdlib, rustcrypto, etc. — meaning a match here is
 * strong evidence the binary computes that hash, even when symbols
 * are gone.
 *
 * We match the IV (first few words) rather than the larger round
 * constants table. The IV is shorter, suffers a slightly higher
 * false-positive rate, but anchoring on the first 4-8 words in the
 * exact published order rules out unrelated tables in practice.
 *
 * MD5 and SHA-1 are flagged as security-category because they are
 * broken; SHA-256 is inventory-only (still secure).
 */

rule md5_constants {
  meta:
    author          = "cradar"
    description     = "MD5 initial state constants in binary (RFC 1321 A,B,C,D)"
    cbom_primitive  = "MD5"
    cbom_asset_type = "algorithm"
    category        = "security"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    /* MD5 IV in little-endian wire order: A=0x67452301, B=0xefcdab89,
     * C=0x98badcfe, D=0x10325476. */
    $iv_le = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 }
  condition:
    $iv_le
}

rule sha1_constants {
  meta:
    author          = "cradar"
    description     = "SHA-1 initial state constants in binary (FIPS 180-4)"
    cbom_primitive  = "SHA-1"
    cbom_asset_type = "algorithm"
    category        = "security"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    /* SHA-1 IV. The constants are H0..H4 = {67452301, efcdab89,
     * 98badcfe, 10325476, c3d2e1f0}. Two layouts in the wild:
     *   - big-endian on-disk: how OpenSSL writes them in lookup tables
     *   - little-endian on x86/ARM uint32_t arrays
     * Matching either covers both static implementations (BE tables)
     * and "C const array of uint32_t" implementations (LE in memory). */
    $iv_be = { 67 45 23 01 ef cd ab 89 98 ba dc fe 10 32 54 76 c3 d2 e1 f0 }
    $iv_le = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 f0 e1 d2 c3 }
  condition:
    any of them
}

rule sha256_constants {
  meta:
    author          = "cradar"
    description     = "SHA-256 initial state constants in binary (FIPS 180-4)"
    cbom_primitive  = "SHA-256"
    cbom_asset_type = "algorithm"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    /* SHA-256 IV: first 32 bits of the fractional parts of the
     * square roots of the first 8 primes. Same two-layout story as
     * SHA-1 — match either BE table or LE uint32_t array. */
    $iv_be = { 6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a
               51 0e 52 7f 9b 05 68 8c 1f 83 d9 ab 5b e0 cd 19 }
    $iv_le = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5
               7f 52 0e 51 8c 68 05 9b ab d9 83 1f 19 cd e0 5b }
  condition:
    any of them
}
