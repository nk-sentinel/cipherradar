package cpp_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/cpp"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/cpp/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/cpp/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "cpp")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("testdata directory not found: %s", dir)
	}
	return dir
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(testdataDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return data
}

// ---------------------------------------------------------------------------
// Basic interface tests
// ---------------------------------------------------------------------------

func TestCppScannerName(t *testing.T) {
	s := cpp.New()
	if s.Name() != "cpp" {
		t.Errorf("expected Name() = %q, got %q", "cpp", s.Name())
	}
}

func TestCppScannerExtensions(t *testing.T) {
	s := cpp.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".c":   true,
		".cpp": true,
		".cc":  true,
		".h":   true,
		".hpp": true,
		".cxx": true,
	}
	if len(exts) != len(expected) {
		t.Fatalf("expected %d extensions, got %d: %v", len(expected), len(exts), exts)
	}
	for _, ext := range exts {
		if !expected[ext] {
			t.Errorf("unexpected extension %q", ext)
		}
	}
}

// ---------------------------------------------------------------------------
// Crypto usage tests
// ---------------------------------------------------------------------------

func TestCryptoUsage(t *testing.T) {
	s := cpp.New()
	content := readFixture(t, "crypto_usage.cpp")
	findings, err := s.ScanFile("crypto_usage.cpp", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.cpp, got none")
	}

	// EVP_EncryptInit
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "block-cipher" &&
			f.RuleID == "cbom-cpp-evp-encryptinit"
	}, "EVP encryption init finding")

	// EVP_DigestInit
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "hash" &&
			f.RuleID == "cbom-cpp-evp-digestinit"
	}, "EVP digest init finding")

	// SHA-256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 hash finding with INFO severity and QuantumSafe status")

	// MD5 (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "MD5 hash finding with HIGH severity and Broken quantum status")

	// SHA-1 (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha1" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "SHA-1 hash finding with HIGH severity and Broken quantum status")

	// RSA-2048 (quantum-vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 2048 &&
			f.Properties.QuantumStatus == types.QuantumVulnerable &&
			f.Name == "RSA-2048"
	}, "RSA-2048 key generation finding with QuantumVulnerable status")

	// AES key setup
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher" &&
			f.RuleID == "cbom-cpp-aes-set-key"
	}, "AES key setup finding")

	// HMAC
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "hmac" &&
			f.Properties.Primitive == "mac"
	}, "HMAC finding")

	// PBKDF2 KDF (quantum-safe, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "PBKDF2" &&
			f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.Properties.Primitive == "kdf" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.QuantumStatus == types.QuantumSafe &&
			f.RuleID == "cbom-cpp-pbkdf2"
	}, "PBKDF2 key derivation finding via PKCS5_PBKDF2_HMAC")

	// PBKDF2 via PKCS5_PBKDF2_HMAC_SHA1 variant
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "PBKDF2" &&
			f.Description == "PBKDF2 key derivation via PKCS5_PBKDF2_HMAC_SHA1()"
	}, "PBKDF2 finding via PKCS5_PBKDF2_HMAC_SHA1")

	// PEM private key
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetRelatedCryptoMaterial &&
			f.Properties.MaterialType == "private-key"
	}, "PEM private key finding")

	// SSL/TLS context
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetProtocol &&
			f.Properties.ProtocolType == "tls"
	}, "SSL/TLS protocol finding")

	// TLS 1.0 (deprecated, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLS 1.0" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.ProtocolVersion == "1.0"
	}, "TLS 1.0 finding with HIGH severity")

	// TLS 1.2 (good, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.ProtocolVersion == "1.2" &&
			f.Severity == types.SeverityInfo
	}, "TLS 1.2 finding with INFO severity")

	// libsodium secretbox
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-cpp-sodium-secretbox" &&
			f.Properties.Primitive == "ae"
	}, "libsodium secretbox finding")

	// libsodium box (public-key)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-cpp-sodium-box"
	}, "libsodium box finding")

	// libsodium sign
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-cpp-sodium-sign" &&
			f.Properties.AlgorithmFamily == "ed25519"
	}, "libsodium sign finding")

	// libsodium AEAD
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-cpp-sodium-aead" &&
			f.Properties.Primitive == "ae"
	}, "libsodium AEAD finding")

	// libsodium password hashing
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-cpp-sodium-pwhash" &&
			f.Properties.AlgorithmFamily == "argon2"
	}, "libsodium password hashing finding")

	// DES (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "DES finding with HIGH severity and Broken quantum status")

	// RC4 (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rc4" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "RC4 finding with HIGH severity and Broken quantum status")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// Language selection tests
// ---------------------------------------------------------------------------

func TestCGrammarForCFile(t *testing.T) {
	s := cpp.New()
	code := []byte(`
#include <openssl/md5.h>

void hash(const unsigned char *data) {
    unsigned char result[16];
    MD5(data, 32, result);
}
`)
	findings, err := s.ScanFile("test.c", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5"
	}, "MD5 finding from .c file")
}

func TestCppGrammarForCppFile(t *testing.T) {
	s := cpp.New()
	code := []byte(`
#include <openssl/sha.h>

void hash(const unsigned char *data) {
    unsigned char result[32];
    SHA256(data, 32, result);
}
`)
	findings, err := s.ScanFile("test.cpp", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256"
	}, "SHA-256 finding from .cpp file")
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	s := cpp.New()

	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`void f() { RSA_generate_key(2048, 65537, NULL, NULL); }`)
		findings, err := s.ScanFile("test.c", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rsa" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "RSA finding with QuantumVulnerable status")
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		code := []byte(`void f() { AES_set_encrypt_key(key, 256, &aes_key); }`)
		findings, err := s.ScanFile("test.c", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.QuantumStatus == types.QuantumSafe
		}, "AES finding with QuantumSafe status")
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		code := []byte(`void f() { MD5(data, len, hash); }`)
		findings, err := s.ScanFile("test.c", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "md5" &&
				f.Properties.QuantumStatus == types.Broken
		}, "MD5 finding with Broken status")
	})

	t.Run("SHA1 is Broken", func(t *testing.T) {
		code := []byte(`void f() { SHA1(data, len, hash); }`)
		findings, err := s.ScanFile("test.c", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "sha1" &&
				f.Properties.QuantumStatus == types.Broken
		}, "SHA-1 finding with Broken status")
	})

	t.Run("DES is Broken", func(t *testing.T) {
		code := []byte(`void f() { DES_set_key(key, &ks); }`)
		findings, err := s.ScanFile("test.c", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "des" &&
				f.Properties.QuantumStatus == types.Broken
		}, "DES finding with Broken status")
	})

	t.Run("RC4 is Broken", func(t *testing.T) {
		code := []byte(`void f() { RC4_set_key(&rc4_key, 16, key); }`)
		findings, err := s.ScanFile("test.c", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rc4" &&
				f.Properties.QuantumStatus == types.Broken
		}, "RC4 finding with Broken status")
	})
}

// ---------------------------------------------------------------------------
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropRSAKeySize(t *testing.T) {
	s := cpp.New()
	code := []byte(`
void f() {
    int bits = 4096;
    RSA_generate_key(bits, 65537, NULL, NULL);
}
`)
	findings, err := s.ScanFile("test.c", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 4096 &&
			f.Name == "RSA-4096"
	}, "RSA-4096 finding via constant propagation")
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := cpp.New()
	findings, err := s.ScanFile("empty.c", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCryptoCpp(t *testing.T) {
	s := cpp.New()
	code := []byte(`
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    int x = 42;
    return 0;
}
`)
	findings, err := s.ScanFile("hello.c", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := cpp.New()
	content := readFixture(t, "crypto_usage.cpp")
	findings, err := s.ScanFile("crypto_usage.cpp", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		if seen[f.ID] {
			t.Errorf("duplicate finding ID: %s", f.ID)
		}
		seen[f.ID] = true
	}
}

func TestFindingIDFormat(t *testing.T) {
	s := cpp.New()
	content := readFixture(t, "crypto_usage.cpp")
	findings, err := s.ScanFile("crypto_usage.cpp", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	for _, f := range findings {
		if len(f.ID) < 6 || f.ID[:5] != "FIND-" {
			t.Errorf("finding ID %q does not match expected FIND-N format", f.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertFindingExists(t *testing.T, findings []types.Finding, match func(types.Finding) bool, description string) {
	t.Helper()
	for _, f := range findings {
		if match(f) {
			return
		}
	}
	t.Errorf("expected to find: %s", description)
	t.Logf("findings were:")
	for _, f := range findings {
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Mode=%s Primitive=%s QS=%s Pass=%d AssetType=%s KeySize=%d",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass, f.AssetType, f.Properties.KeySize)
	}
}
