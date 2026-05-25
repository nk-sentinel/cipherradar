/*
 * OpenSSL version strings in compiled binaries.
 *
 * Static-linked OpenSSL leaves its build banner in .rodata. The banner is
 * the signal CVE matching needs (which OpenSSL major.minor is shipped).
 * Each rule below detects one OpenSSL minor series — 1.0.x, 1.1.x, 3.0.x,
 * 3.1.x. We split by minor (rather than one omnibus rule) so the
 * cbom_primitive token is precise enough for portfolio queries like
 * "show me every artifact on OpenSSL 1.0".
 *
 * The `\s|\x00` tail anchors to either a runtime space (banner) or a NUL
 * (C string terminator), which keeps the pattern from matching arbitrary
 * version-shaped substrings inside packed data.
 */

rule openssl_version_1_0 {
  meta:
    author          = "cradar"
    description     = "OpenSSL 1.0.x version string embedded in binary"
    cbom_primitive  = "OPENSSL-1.0"
    cbom_asset_type = "library"
    cbom_library    = "openssl"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $ver = /OpenSSL 1\.0\.[0-9]+[a-z]?(\s|\x00)/
  condition:
    $ver
}

rule openssl_version_1_1 {
  meta:
    author          = "cradar"
    description     = "OpenSSL 1.1.x version string embedded in binary"
    cbom_primitive  = "OPENSSL-1.1"
    cbom_asset_type = "library"
    cbom_library    = "openssl"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $ver = /OpenSSL 1\.1\.[0-9]+[a-z]?(\s|\x00)/
  condition:
    $ver
}

rule openssl_version_3_0 {
  meta:
    author          = "cradar"
    description     = "OpenSSL 3.0.x version string embedded in binary"
    cbom_primitive  = "OPENSSL-3.0"
    cbom_asset_type = "library"
    cbom_library    = "openssl"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $ver = /OpenSSL 3\.0\.[0-9]+(\s|\x00)/
  condition:
    $ver
}

rule openssl_version_3_1 {
  meta:
    author          = "cradar"
    description     = "OpenSSL 3.1.x version string embedded in binary"
    cbom_primitive  = "OPENSSL-3.1"
    cbom_asset_type = "library"
    cbom_library    = "openssl"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $ver = /OpenSSL 3\.1\.[0-9]+(\s|\x00)/
  condition:
    $ver
}
