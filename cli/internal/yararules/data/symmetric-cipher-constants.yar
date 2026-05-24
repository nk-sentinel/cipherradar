/*
 * Symmetric cipher constants in compiled binaries.
 *
 * AES and DES are defined by fixed byte tables (S-boxes, round
 * constants). A static-linked or hand-rolled implementation embeds
 * those tables in .rodata. The byte sequence is the same in every
 * implementation — there's no portable way to express AES without it —
 * so matching the table is a high-precision signal that the binary
 * speaks AES (or DES), even after symbol stripping or obfuscation.
 *
 * Forward and inverse S-boxes get separate rules because some
 * implementations only need the forward path (encryption) and some
 * only the inverse (key schedule / decryption). Detecting both is
 * stronger evidence; detecting one is still positive evidence.
 */

rule aes_sbox_forward {
  meta:
    author          = "cradar"
    description     = "AES forward S-box byte sequence in binary (FIPS 197 Table 4)"
    cbom_primitive  = "AES"
    cbom_asset_type = "algorithm"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    /* First 16 bytes of the AES forward S-box. */
    $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
  condition:
    $sbox
}

rule aes_sbox_inverse {
  meta:
    author          = "cradar"
    description     = "AES inverse S-box byte sequence in binary (FIPS 197 Table 6)"
    cbom_primitive  = "AES"
    cbom_asset_type = "algorithm"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    /* First 16 bytes of the AES inverse S-box. */
    $invsbox = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
  condition:
    $invsbox
}

rule aes_rcon {
  meta:
    author          = "cradar"
    description     = "AES round constants (Rcon) in binary"
    cbom_primitive  = "AES"
    cbom_asset_type = "algorithm"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    /* First 10 Rcon values; sufficient for AES-128/192/256 key schedules.
     * Anchored with the first value 0x01 — matching all 10 in sequence
     * rules out the obvious false-positive of a lone 0x01 byte. */
    $rcon = { 01 02 04 08 10 20 40 80 1b 36 }
  condition:
    $rcon
}

rule des_sbox {
  meta:
    author          = "cradar"
    description     = "DES S-box byte sequence in binary (S-box 1, first row)"
    cbom_primitive  = "DES"
    cbom_asset_type = "algorithm"
    category        = "security"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "medium"
  strings:
    /* DES S-box 1, first row (FIPS 46-3). DES S-box tables are stored
     * in many in-memory layouts; this rule targets the canonical
     * row-major layout used in libcrypto-style implementations.
     * Noise risk is medium because the byte sequence is short enough
     * to occasionally appear in unrelated tables. */
    $sbox1 = { 0e 04 0d 01 02 0f 0b 08 03 0a 06 0c 05 09 00 07 }
  condition:
    $sbox1
}
