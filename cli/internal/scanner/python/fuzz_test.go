package python_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
)

func FuzzPythonScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not python code at all"))
	f.Add([]byte("import hashlib\nhashlib.md5(b'test')"))
	f.Add([]byte("from cryptography.hazmat.primitives.ciphers import Cipher"))
	f.Add([]byte("import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS)"))
	f.Add([]byte("from Crypto.Cipher import AES"))
	f.Add([]byte("import hmac\nhmac.new(b'key', b'msg', hashlib.sha256)"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("hashlib.new("))
	f.Add([]byte("def foo():\n    pass"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := python.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.py", data)
	})
}
