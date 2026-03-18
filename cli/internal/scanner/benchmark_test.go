package scanner_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/javascript"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
)

// ---------------------------------------------------------------------------
// Fixture content: representative crypto-heavy source files
// ---------------------------------------------------------------------------

const pythonFixture = `import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def hash_password(password):
    md5_hash = hashlib.md5(password.encode())
    sha1_hash = hashlib.sha1(password.encode())
    sha256_hash = hashlib.sha256(password.encode())
    algo = "sha512"
    dynamic_hash = hashlib.new(algo)
    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 100000)
    return derived_key

def encrypt_data(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def generate_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    return rsa_key, ec_key

def hash_data(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password)
`

const javascriptFixture = `const crypto = require('crypto');

const md5Hash = crypto.createHash('md5').update('data').digest('hex');
const sha256Hash = crypto.createHash('sha256').update('data').digest('hex');
const desCipher = crypto.createCipher('des', 'password');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const aesCipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});
const hmac = crypto.createHmac('sha256', 'secret');
crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');
const ecdh = crypto.createECDH('secp256k1');
`

const javaFixture = `import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;
import javax.net.ssl.SSLContext;

public class CryptoExample {
    public void encryptDES(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
    }
    public void encryptAESECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
    public void encryptAESGCM(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
    public byte[] hashMD5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }
    public byte[] hashSHA1(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }
    public byte[] hashSHA256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
    public void generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
    public void signData() throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
    }
    public void computeHMAC() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
    }
    public void secureTLS() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    }
    public void constPropTest() throws Exception {
        String algo = "AES/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algo);
    }
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// createFixtureDir creates a temp directory with the specified fixture files.
// Returns the directory path. The caller is responsible for cleanup (handled by b.TempDir).
func createFixtureDir(b *testing.B, files map[string]string) string {
	b.Helper()
	dir := b.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		subDir := filepath.Dir(path)
		if subDir != dir {
			if err := os.MkdirAll(subDir, 0755); err != nil {
				b.Fatalf("failed to create subdirectory %s: %v", subDir, err)
			}
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			b.Fatalf("failed to write fixture %s: %v", name, err)
		}
	}
	return dir
}

// newDefaultRegistry creates a registry with all production scanners.
func newDefaultRegistry() *scanner.Registry {
	r := scanner.NewRegistry()
	r.Register(python.New())
	r.Register(javascript.New())
	r.Register(java.New())
	return r
}

// ---------------------------------------------------------------------------
// ScanDir benchmarks — directory scanning with worker pool
// ---------------------------------------------------------------------------

func BenchmarkScanDir_PythonFiles(b *testing.B) {
	files := make(map[string]string)
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("pkg%d/crypto_%d.py", i/5, i)] = pythonFixture
	}
	dir := createFixtureDir(b, files)
	registry := newDefaultRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanDir(dir, registry, []int{1})
		if err != nil {
			b.Fatalf("ScanDir error: %v", err)
		}
		if result.FilesScanned == 0 {
			b.Fatal("no files scanned")
		}
	}
}

func BenchmarkScanDir_JavaScriptFiles(b *testing.B) {
	files := make(map[string]string)
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("src%d/crypto_%d.js", i/5, i)] = javascriptFixture
	}
	dir := createFixtureDir(b, files)
	registry := newDefaultRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanDir(dir, registry, []int{1})
		if err != nil {
			b.Fatalf("ScanDir error: %v", err)
		}
		if result.FilesScanned == 0 {
			b.Fatal("no files scanned")
		}
	}
}

func BenchmarkScanDir_JavaFiles(b *testing.B) {
	files := make(map[string]string)
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("com/example/pkg%d/Crypto%d.java", i/5, i)] = javaFixture
	}
	dir := createFixtureDir(b, files)
	registry := newDefaultRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanDir(dir, registry, []int{1})
		if err != nil {
			b.Fatalf("ScanDir error: %v", err)
		}
		if result.FilesScanned == 0 {
			b.Fatal("no files scanned")
		}
	}
}

func BenchmarkScanDir_MixedProject(b *testing.B) {
	files := make(map[string]string)
	// 10 Python files
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("python/module%d/crypto_%d.py", i/3, i)] = pythonFixture
	}
	// 10 JavaScript files
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("js/src%d/crypto_%d.js", i/3, i)] = javascriptFixture
	}
	// 10 Java files
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("java/com/example/pkg%d/Crypto%d.java", i/3, i)] = javaFixture
	}
	dir := createFixtureDir(b, files)
	registry := newDefaultRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanDir(dir, registry, []int{1})
		if err != nil {
			b.Fatalf("ScanDir error: %v", err)
		}
		if result.FilesScanned == 0 {
			b.Fatal("no files scanned")
		}
	}
}

func BenchmarkScanDir_LargeProject(b *testing.B) {
	files := make(map[string]string)
	// 50 Python files
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("python/pkg%d/sub%d/crypto_%d.py", i/10, i/5, i)] = pythonFixture
	}
	// 50 JavaScript files
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("js/src%d/lib%d/crypto_%d.js", i/10, i/5, i)] = javascriptFixture
	}
	// 50 Java files
	for i := 0; i < 50; i++ {
		files[fmt.Sprintf("java/com/example/pkg%d/sub%d/Crypto%d.java", i/10, i/5, i)] = javaFixture
	}
	dir := createFixtureDir(b, files)
	registry := newDefaultRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanDir(dir, registry, []int{1})
		if err != nil {
			b.Fatalf("ScanDir error: %v", err)
		}
		if result.FilesScanned == 0 {
			b.Fatal("no files scanned")
		}
	}
}

// ---------------------------------------------------------------------------
// Single-file scanner benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPythonScanner_SingleFile(b *testing.B) {
	s := python.New()
	content := []byte(pythonFixture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.ScanFile("test.py", content)
		if err != nil {
			b.Fatalf("ScanFile error: %v", err)
		}
	}
}

func BenchmarkJavaScriptScanner_SingleFile(b *testing.B) {
	s := javascript.New()
	content := []byte(javascriptFixture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.ScanFile("test.js", content)
		if err != nil {
			b.Fatalf("ScanFile error: %v", err)
		}
	}
}

func BenchmarkJavaScanner_SingleFile(b *testing.B) {
	s := java.New()
	content := []byte(javaFixture)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.ScanFile("Test.java", content)
		if err != nil {
			b.Fatalf("ScanFile error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Single-file scanner benchmarks with real testdata files
// ---------------------------------------------------------------------------

func BenchmarkPythonScanner_CryptographyUsage(b *testing.B) {
	content, err := os.ReadFile("../../testdata/python/cryptography_usage.py")
	if err != nil {
		b.Skipf("testdata not available: %v", err)
	}
	s := python.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.ScanFile("cryptography_usage.py", content)
		if err != nil {
			b.Fatalf("ScanFile error: %v", err)
		}
	}
}

func BenchmarkJavaScriptScanner_CryptoUsage(b *testing.B) {
	content, err := os.ReadFile("../../testdata/javascript/crypto_usage.js")
	if err != nil {
		b.Skipf("testdata not available: %v", err)
	}
	s := javascript.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.ScanFile("crypto_usage.js", content)
		if err != nil {
			b.Fatalf("ScanFile error: %v", err)
		}
	}
}

func BenchmarkJavaScanner_JcaCrypto(b *testing.B) {
	content, err := os.ReadFile("../../testdata/java/JcaCrypto.java")
	if err != nil {
		b.Skipf("testdata not available: %v", err)
	}
	s := java.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.ScanFile("JcaCrypto.java", content)
		if err != nil {
			b.Fatalf("ScanFile error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Parallel-safety stress test benchmark
// ---------------------------------------------------------------------------

func BenchmarkScanDir_ParallelStress(b *testing.B) {
	// Creates many small files to stress the worker pool and channel machinery.
	files := make(map[string]string)
	for i := 0; i < 100; i++ {
		switch i % 3 {
		case 0:
			files[fmt.Sprintf("stress/file_%d.py", i)] = pythonFixture
		case 1:
			files[fmt.Sprintf("stress/file_%d.js", i)] = javascriptFixture
		case 2:
			files[fmt.Sprintf("stress/file_%d.java", i)] = javaFixture
		}
	}
	dir := createFixtureDir(b, files)
	registry := newDefaultRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := scanner.ScanDir(dir, registry, []int{1})
		if err != nil {
			b.Fatalf("ScanDir error: %v", err)
		}
		if result.FilesScanned != 100 {
			b.Fatalf("expected 100 files scanned, got %d", result.FilesScanned)
		}
	}
}
