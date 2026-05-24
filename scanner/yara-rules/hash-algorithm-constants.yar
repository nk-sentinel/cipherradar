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
    /* SHA-1 IV in big-endian on-disk order: 67452301 efcdab89 98badcfe
     * 10325476 c3d2e1f0. */
    $iv_be = { 67 45 23 01 ef cd ab 89 98 ba dc fe 10 32 54 76 c3 d2 e1 f0 }
  condition:
    $iv_be
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
    /* SHA-256 IV in big-endian on-disk order: first 32 bits of the
     * fractional parts of the square roots of the first 8 primes.
     * Matching all 8 in order makes this near-zero false-positive. */
    $iv_be = { 6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a
               51 0e 52 7f 9b 05 68 8c 1f 83 d9 ab 5b e0 cd 19 }
  condition:
    $iv_be
}
