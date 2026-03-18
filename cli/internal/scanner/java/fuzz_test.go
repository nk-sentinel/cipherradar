package java_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
)

func FuzzJavaScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not java"))
	f.Add([]byte("import javax.crypto.Cipher; Cipher.getInstance(\"AES\");"))
	f.Add([]byte("import java.security.MessageDigest; MessageDigest.getInstance(\"MD5\");"))
	f.Add([]byte("new AESEngine();"))
	f.Add([]byte("new CBCBlockCipher(new AESEngine());"))
	f.Add([]byte("SSLContext.getInstance(\"TLSv1.2\");"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("Cipher.getInstance("))
	f.Add([]byte("public class Test { public static void main(String[] args) { } }"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := java.New()
		// Must not panic on any input
		_, _ = s.ScanFile("Test.java", data)
	})
}
