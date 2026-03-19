package ruby_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/ruby"
)

func FuzzRubyScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not ruby code at all"))
	f.Add([]byte("require 'openssl'\ncipher = OpenSSL::Cipher.new('AES-256-CBC')"))
	f.Add([]byte("digest = OpenSSL::Digest::SHA256.new"))
	f.Add([]byte("rsa = OpenSSL::PKey::RSA.new(2048)"))
	f.Add([]byte("ssl = OpenSSL::SSL::SSLContext.new"))
	f.Add([]byte("hash = BCrypt::Password.create('secret')"))
	f.Add([]byte("Digest::MD5.hexdigest('data')"))
	f.Add([]byte("Digest::SHA256.hexdigest('data')"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("def foo\n  42\nend"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := ruby.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.rb", data)
	})
}
