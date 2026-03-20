// Test fixture: SSL/TLS certificate validation bypass patterns.
// SSL_CTX_set_verify with SSL_VERIFY_NONE or callbacks that always return 1.

#include <openssl/ssl.h>
#include <openssl/x509.h>

// Custom verify callback that always returns 1 — should be detected.
static int always_true_verify(int preverify_ok, X509_STORE_CTX *ctx) {
    // Ignoring certificate errors — security bypass!
    return 1;
}

// Another always-true callback variant.
static int ignore_cert_errors(int ok, X509_STORE_CTX *store) {
    (void)ok;
    (void)store;
    return 1;
}

// SSL_VERIFY_NONE — should be detected (critical).
SSL_CTX *create_insecure_context_none(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    // Disables all certificate verification.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

// SSL_VERIFY_NONE with literal 0 — should be detected.
SSL_CTX *create_insecure_context_zero(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    // SSL_VERIFY_NONE == 0
    SSL_CTX_set_verify(ctx, 0, NULL);

    return ctx;
}

// SSL_CTX_set_verify with always-true callback — should be detected.
SSL_CTX *create_insecure_context_callback(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    // Callback always returns 1, ignoring all cert errors.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, always_true_verify);

    return ctx;
}

// Per-connection SSL_set_verify with VERIFY_NONE — should be detected.
void disable_verify_per_connection(SSL *ssl) {
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
}

// Per-connection with literal 0 — should be detected.
void disable_verify_per_connection_zero(SSL *ssl) {
    SSL_set_verify(ssl, 0, NULL);
}

// SSL_CTX_set_cert_verify_callback with always-true — should be detected.
static int always_accept_cert(X509_STORE_CTX *ctx, void *arg) {
    return 1;
}

SSL_CTX *create_insecure_cert_verify(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_cert_verify_callback(ctx, always_accept_cert, NULL);
    return ctx;
}

// Safe example: proper certificate verification — should NOT be detected.
SSL_CTX *create_secure_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    // Proper verification enabled.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // Load trusted CA certificates.
    SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL);

    return ctx;
}

// Safe callback: actually checks the certificate — should NOT be detected.
static int proper_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        // Log the error and reject
        fprintf(stderr, "Certificate verify error: %d\n", err);
        return 0;  // Reject invalid certificates
    }
    return preverify_ok;
}

SSL_CTX *create_secure_context_with_callback(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, proper_verify_callback);
    return ctx;
}
