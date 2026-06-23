package php_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/php"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/php/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/php/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "php")
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

func TestPHPScannerName(t *testing.T) {
	s := php.New()
	if s.Name() != "php" {
		t.Errorf("expected Name() = %q, got %q", "php", s.Name())
	}
}

func TestPHPScannerExtensions(t *testing.T) {
	s := php.New()
	exts := s.Extensions()
	expected := map[string]bool{".php": true}
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
// openssl_encrypt / openssl_decrypt tests
// ---------------------------------------------------------------------------

func TestOpenSSLEncryptDecrypt(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.php, got none")
	}

	// AES-256-CBC via openssl_encrypt
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc" &&
			f.Severity == types.SeverityInfo
	}, "AES-256-CBC finding via openssl_encrypt")

	// DES-ECB (HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Properties.Mode == "ecb" &&
			f.Severity == types.SeverityHigh
	}, "DES-ECB finding with HIGH severity")

	// AES-128-GCM
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm" &&
			f.Severity == types.SeverityInfo
	}, "AES-128-GCM finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

func TestOpenSSLSign(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// openssl_sign with OPENSSL_ALGO_SHA256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "signature" &&
			f.Properties.CryptoFunctions != nil &&
			containsString(f.Properties.CryptoFunctions, "sign")
	}, "openssl_sign finding")
}

func TestOpenSSLPkeyNew(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// RSA key generation
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.CryptoFunctions != nil &&
			containsString(f.Properties.CryptoFunctions, "generate")
	}, "RSA key generation via openssl_pkey_new")

	// EC key generation
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ec" &&
			f.Properties.CryptoFunctions != nil &&
			containsString(f.Properties.CryptoFunctions, "generate")
	}, "EC key generation via openssl_pkey_new")
}

func TestOpenSSLPkeyNewPrivateKeyBits(t *testing.T) {
	s := php.New()
	src := `<?php
$key = openssl_pkey_new([
    'private_key_bits' => 4096,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
`
	findings, err := s.ScanFile("keygen.php", []byte(src))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" && f.Properties.KeySize == 4096
	}, "RSA keygen with private_key_bits=4096")
}

// ---------------------------------------------------------------------------
// hash / hash_hmac / hash_pbkdf2 tests
// ---------------------------------------------------------------------------

func TestHashFunctions(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// MD5 (HIGH severity, broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "MD5" && f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "MD5 finding with Broken quantum status and HIGH severity")

	// SHA-1 (HIGH severity, broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-1" && f.Properties.AlgorithmFamily == "sha1" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "SHA-1 finding with Broken quantum status and HIGH severity")

	// SHA-256 (INFO, quantum safe)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" && f.Properties.AlgorithmFamily == "sha-256" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 finding with QuantumSafe status and INFO severity")

	// SHA-512
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-512" && f.Properties.AlgorithmFamily == "sha-512"
	}, "SHA-512 finding")
}

func TestHashHMAC(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// HMAC-SHA256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "mac" &&
			f.Properties.AlgorithmFamily == "sha-256"
	}, "HMAC-SHA256 finding")
}

func TestHashPBKDF2(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// PBKDF2 finding
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "kdf" &&
			f.Properties.AlgorithmFamily == "pbkdf2"
	}, "PBKDF2 finding via hash_pbkdf2()")
}

// ---------------------------------------------------------------------------
// password_hash / password_verify tests
// ---------------------------------------------------------------------------

func TestPasswordHash(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// bcrypt via password_hash
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bcrypt" &&
			f.Properties.Primitive == "kdf"
	}, "bcrypt finding via password_hash()")

	// Argon2id via password_hash
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "argon2" &&
			f.Properties.Primitive == "kdf"
	}, "Argon2id finding via password_hash()")

	// password_verify
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-php-password_verify-verify"
	}, "password_verify finding")
}

// ---------------------------------------------------------------------------
// Sodium tests
// ---------------------------------------------------------------------------

func TestSodiumFunctions(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// sodium_crypto_secretbox (XSalsa20-Poly1305)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "xsalsa20" &&
			f.Properties.Primitive == "ae"
	}, "sodium_crypto_secretbox finding")

	// sodium_crypto_box (X25519)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "x25519" &&
			f.Properties.Primitive == "pke"
	}, "sodium_crypto_box finding")

	// sodium_crypto_sign (Ed25519)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ed25519" &&
			f.Properties.Primitive == "signature"
	}, "sodium_crypto_sign finding")

	// sodium_crypto_aead_chacha20poly1305_encrypt
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "chacha20" &&
			f.Properties.Primitive == "ae"
	}, "sodium_crypto_aead_chacha20poly1305_encrypt finding")
}

// ---------------------------------------------------------------------------
// mcrypt tests
// ---------------------------------------------------------------------------

func TestMcryptDeprecated(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// mcrypt_encrypt should be HIGH severity
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Severity == types.SeverityHigh &&
			f.RuleID == "cbom-php-mcrypt_encrypt-deprecated"
	}, "mcrypt_encrypt finding with HIGH severity")
}

// ---------------------------------------------------------------------------
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropagation(t *testing.T) {
	t.Run("openssl_encrypt with variable method", func(t *testing.T) {
		s := php.New()
		code := []byte(`<?php
$method = 'AES-256-CBC';
$encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
`)
		findings, err := s.ScanFile("test.php", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.Mode == "cbc" &&
				f.Confidence == types.ConfidenceMedium
		}, "openssl_encrypt with constprop-resolved AES-256-CBC")
	})

	t.Run("hash with variable algorithm", func(t *testing.T) {
		s := php.New()
		code := []byte(`<?php
$algo = 'sha256';
$h = hash($algo, $data);
`)
		findings, err := s.ScanFile("test.php", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "sha-256" &&
				f.Properties.Primitive == "hash" &&
				f.Confidence == types.ConfidenceMedium
		}, "hash() with constprop-resolved sha256")
	})

	t.Run("direct constprop API", func(t *testing.T) {
		cp := php.NewConstPropagator()
		cp.Set("test_var", "test_value")
		val, ok := cp.Resolve("test_var")
		if !ok {
			t.Fatal("expected Resolve to return true")
		}
		if val != "test_value" {
			t.Errorf("expected %q, got %q", "test_value", val)
		}
	})

	t.Run("unresolved variable returns empty", func(t *testing.T) {
		cp := php.NewConstPropagator()
		_, ok := cp.Resolve("nonexistent")
		if ok {
			t.Error("expected Resolve for nonexistent variable to return false")
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := php.New()
	findings, err := s.ScanFile("empty.php", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCrypto(t *testing.T) {
	s := php.New()
	code := []byte(`<?php
function hello() {
    echo "Hello, world!";
    $x = 42;
    return $x;
}

hello();
`)
	findings, err := s.ScanFile("no_crypto.php", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
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
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	for _, f := range findings {
		if len(f.ID) < 6 || f.ID[:5] != "FIND-" {
			t.Errorf("finding ID %q does not match expected FIND-N format", f.ID)
		}
	}
}

func TestAllFindingsPass1(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s (%s) has Pass=%d, expected 1", f.ID, f.RuleID, f.Pass)
		}
	}
}

func TestRuleIDPrefix(t *testing.T) {
	s := php.New()
	content := readFixture(t, "crypto_usage.php")
	findings, err := s.ScanFile("crypto_usage.php", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	for _, f := range findings {
		if len(f.RuleID) < 8 || f.RuleID[:8] != "cbom-php" {
			t.Errorf("finding %s has RuleID %q which does not start with cbom-php", f.ID, f.RuleID)
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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Mode=%s Primitive=%s QS=%s Pass=%d",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass)
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
