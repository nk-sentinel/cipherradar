/*
 * Non-OpenSSL crypto library signatures.
 *
 * Each rule matches a fingerprint that the linker leaves in .rodata when
 * an application statically links the library. The signal is uniformity
 * across builds: even when symbols are stripped, the embedded version /
 * banner string survives because the library code itself reads it at
 * runtime.
 *
 * Coverage rationale: libsodium, BoringSSL, and mbedTLS together cover
 * the majority of non-OpenSSL TLS / NaCl-style crypto stacks shipped in
 * embedded firmware and Go/Rust binaries. wolfSSL / nss / GnuTLS get
 * their own file later if user demand justifies it.
 */

rule libsodium_signature {
  meta:
    author          = "cradar"
    description     = "libsodium library symbol or version string in binary"
    cbom_primitive  = "LIBSODIUM"
    cbom_asset_type = "library"
    cbom_library    = "libsodium"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $sym  = "sodium_init"
    $ver  = /libsodium [0-9]+\.[0-9]+\.[0-9]+/
  condition:
    any of them
}

rule boringssl_magic {
  meta:
    author          = "cradar"
    description     = "BoringSSL build banner or namespace marker in binary"
    cbom_primitive  = "BORINGSSL"
    cbom_asset_type = "library"
    cbom_library    = "boringssl"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $banner   = "BoringSSL"
    $namespace = "bssl::"
  condition:
    any of them
}

rule mbedtls_signature {
  meta:
    author          = "cradar"
    description     = "mbed TLS version string or function namespace in binary"
    cbom_primitive  = "MBEDTLS"
    cbom_asset_type = "library"
    cbom_library    = "mbedtls"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $ver    = /mbed TLS [0-9]+\.[0-9]+\.[0-9]+/
    $prefix = "mbedtls_"
  condition:
    any of them
}
