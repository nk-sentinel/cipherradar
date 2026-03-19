package swift_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/swift"
)

func FuzzSwiftScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not swift code at all"))
	f.Add([]byte("import CryptoKit\nlet sealed = try AES.GCM.seal(data, using: key)"))
	f.Add([]byte("let digest = SHA256.hash(data: input)"))
	f.Add([]byte("CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), 0, key, keyLength, iv, data, dataLength, buffer, bufferSize, &out)"))
	f.Add([]byte("CC_MD5(data, CC_LONG(data.count), &digest)"))
	f.Add([]byte("let key = P256.Signing.PrivateKey()"))
	f.Add([]byte("let cert = SecCertificateCreateWithData(nil, data)"))
	f.Add([]byte("let key = SymmetricKey(size: .bits256)"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("func foo() {\n    return\n}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := swift.New()
		// Must not panic on any input
		_, _ = s.ScanFile("test.swift", data)
	})
}
