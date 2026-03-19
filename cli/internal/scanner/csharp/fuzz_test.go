package csharp_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/csharp"
)

func FuzzCSharpScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not csharp"))
	f.Add([]byte("Aes.Create();"))
	f.Add([]byte("MD5.Create();"))
	f.Add([]byte("SHA256.Create();"))
	f.Add([]byte("RSA.Create(2048);"))
	f.Add([]byte("DES.Create();"))
	f.Add([]byte("TripleDES.Create();"))
	f.Add([]byte("ECDsa.Create();"))
	f.Add([]byte("new HMACSHA256(key);"))
	f.Add([]byte("new Rfc2898DeriveBytes(\"password\", salt, 100000);"))
	f.Add([]byte("SslProtocols.Tls12"))
	f.Add([]byte("SslProtocols.Tls"))
	f.Add([]byte("new AesEngine();"))
	f.Add([]byte("new DesEngine();"))
	f.Add([]byte("new RsaEngine();"))
	f.Add([]byte("new Sha256Digest();"))
	f.Add([]byte("new MD5Digest();"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("Aes.Create("))
	f.Add([]byte("class Program { static void Main() { Console.WriteLine(\"hello\"); } }"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := csharp.New()
		// Must not panic on any input
		_, _ = s.ScanFile("Test.cs", data)
	})
}
