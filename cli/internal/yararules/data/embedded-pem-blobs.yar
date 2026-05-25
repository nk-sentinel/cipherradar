/*
 * Embedded PEM material in compiled binaries.
 *
 * Leak vector: a developer pastes a key or cert into a string literal
 * "just for testing" and ships the binary. The BEGIN/END markers survive
 * stripping and compression, and detecting them flags artifacts that
 * carry hard-coded private-key material — a high-signal finding because
 * the leak is almost always unintentional.
 *
 * Four rules cover the common PEM types: X.509 certificates, RSA
 * private keys (PKCS#1), EC private keys (SEC1), and PKCS#8 (unwrapped)
 * private keys.
 *
 * cbom_asset_type is "certificate" for the cert rule and
 * "related-crypto-material" for the private-key rules — matches the
 * CycloneDX 1.7 asset-type vocabulary used by other passes.
 */

rule embedded_pem_certificate {
  meta:
    author          = "cradar"
    description     = "Embedded X.509 PEM certificate in binary"
    cbom_primitive  = "X.509"
    cbom_asset_type = "certificate"
    category        = "inventory"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $begin = "-----BEGIN CERTIFICATE-----"
    $end   = "-----END CERTIFICATE-----"
  condition:
    $begin and $end
}

rule embedded_pem_rsa_private {
  meta:
    author          = "cradar"
    description     = "Embedded PKCS#1 RSA private key in binary"
    cbom_primitive  = "RSA"
    cbom_asset_type = "related-crypto-material"
    category        = "security"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $begin = "-----BEGIN RSA PRIVATE KEY-----"
    $end   = "-----END RSA PRIVATE KEY-----"
  condition:
    $begin and $end
}

rule embedded_pem_ec_private {
  meta:
    author          = "cradar"
    description     = "Embedded SEC1 EC private key in binary"
    cbom_primitive  = "ECDSA"
    cbom_asset_type = "related-crypto-material"
    category        = "security"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $begin = "-----BEGIN EC PRIVATE KEY-----"
    $end   = "-----END EC PRIVATE KEY-----"
  condition:
    $begin and $end
}

rule embedded_pkcs8_private {
  meta:
    author          = "cradar"
    description     = "Embedded PKCS#8 unwrapped private key in binary"
    cbom_primitive  = "PKCS8"
    cbom_asset_type = "related-crypto-material"
    category        = "security"
    maturity        = "stable"
    default_enabled = "true"
    noise_risk      = "low"
  strings:
    $begin = "-----BEGIN PRIVATE KEY-----"
    $end   = "-----END PRIVATE KEY-----"
  condition:
    $begin and $end
}
