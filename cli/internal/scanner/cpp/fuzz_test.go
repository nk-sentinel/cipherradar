package cpp_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/cpp"
)

func FuzzCppScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not c code"))
	f.Add([]byte("void f() { SHA256(data, len, hash); }"))
	f.Add([]byte("void f() { MD5(data, len, hash); }"))
	f.Add([]byte("void f() { SHA1(data, len, hash); }"))
	f.Add([]byte("void f() { RSA_generate_key(2048, 65537, NULL, NULL); }"))
	f.Add([]byte("void f() { EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv); }"))
	f.Add([]byte("void f() { SSL_CTX_new(TLS_method()); }"))
	f.Add([]byte("void f() { crypto_secretbox_easy(c, m, 64, n, k); }"))
	f.Add([]byte("void f() { crypto_pwhash_str(h, p, l, ops, mem); }"))
	f.Add([]byte("void f() { mbedtls_aes_init(&ctx); }"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("void f() { EVP_EncryptInit("))
	f.Add([]byte("int main() { return 0; }"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := cpp.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.cpp", data)
	})
}
