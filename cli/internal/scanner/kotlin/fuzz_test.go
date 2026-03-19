package kotlin_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kotlin"
)

func FuzzKotlinScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not kotlin"))
	f.Add([]byte("import javax.crypto.Cipher; Cipher.getInstance(\"AES\");"))
	f.Add([]byte("import java.security.MessageDigest; MessageDigest.getInstance(\"MD5\");"))
	f.Add([]byte("new AESEngine();"))
	f.Add([]byte("new CBCBlockCipher(new AESEngine());"))
	f.Add([]byte("SSLContext.getInstance(\"TLSv1.2\");"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("Cipher.getInstance("))
	f.Add([]byte("fun main() { println(\"hello\") }"))
	f.Add([]byte("val cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")"))
	f.Add([]byte("const val ALGORITHM = \"AES/CBC/PKCS5Padding\""))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := kotlin.New()
		// Must not panic on any input
		_, _ = s.ScanFile("Test.kt", data)
	})
}
