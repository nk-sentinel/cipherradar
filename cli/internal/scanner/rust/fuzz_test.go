package rust_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/rust"
)

func FuzzRustScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not rust code"))
	f.Add([]byte("fn f() { let h = digest::digest(&digest::SHA256, data); }"))
	f.Add([]byte("fn f() { let h = digest::digest(&digest::SHA1, data); }"))
	f.Add([]byte("fn f() { let k = aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap(); }"))
	f.Add([]byte("fn f() { let pk = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap(); }"))
	f.Add([]byte("fn f() { pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, n, salt, pass, &mut key); }"))
	f.Add([]byte("fn f() { let kp = signature::Ed25519KeyPair::from_pkcs8(bytes).unwrap(); }"))
	f.Add([]byte("fn f() { let config = ClientConfig::builder().with_safe_defaults(); }"))
	f.Add([]byte("fn f() { let rsa = openssl::rsa::Rsa::generate(2048).unwrap(); }"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("fn f() { digest::digest("))
	f.Add([]byte("fn main() {}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := rust.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.rs", data)
	})
}
