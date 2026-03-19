package golang_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/golang"
)

func FuzzGoScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not go code"))
	f.Add([]byte("package main\nimport \"crypto/aes\"\nfunc f() { aes.NewCipher(nil) }"))
	f.Add([]byte("package main\nimport \"crypto/md5\"\nfunc f() { md5.Sum(nil) }"))
	f.Add([]byte("package main\nimport \"crypto/sha1\"\nfunc f() { sha1.New() }"))
	f.Add([]byte("package main\nimport \"crypto/rsa\"\nimport \"crypto/rand\"\nfunc f() { rsa.GenerateKey(rand.Reader, 2048) }"))
	f.Add([]byte("package main\nimport \"crypto/tls\"\nfunc f() { _ = &tls.Config{MinVersion: tls.VersionTLS12} }"))
	f.Add([]byte("package main\nimport \"golang.org/x/crypto/bcrypt\"\nfunc f() { bcrypt.GenerateFromPassword(nil, 10) }"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("package main\nimport \"crypto/aes\"\nfunc f() { aes.NewCipher("))
	f.Add([]byte("package main\nfunc main() {}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := golang.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.go", data)
	})
}
