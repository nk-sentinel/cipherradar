package dart_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/dart"
)

func FuzzDartScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not dart code at all"))
	f.Add([]byte("var result = sha256.convert(utf8.encode('data'));"))
	f.Add([]byte("var result = sha1.convert(utf8.encode('data'));"))
	f.Add([]byte("var result = md5.convert(utf8.encode('data'));"))
	f.Add([]byte("var hmac = Hmac(sha256, key);"))
	f.Add([]byte("var engine = AESFastEngine();"))
	f.Add([]byte("var rsa = RSAEngine();"))
	f.Add([]byte("var digest = SHA256Digest();"))
	f.Add([]byte("var kdf = PBKDF2KeyDerivator(hmac);"))
	f.Add([]byte("var rng = FortunaRandom();"))
	f.Add([]byte("var enc = Encrypter(AES(key));"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("void main() {\n  print('hello');\n}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := dart.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.dart", data)
	})
}
