package rust_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/rust"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/rust/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/rust/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "rust")
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

func TestRustScannerName(t *testing.T) {
	s := rust.New()
	if s.Name() != "rust" {
		t.Errorf("expected Name() = %q, got %q", "rust", s.Name())
	}
}

func TestRustScannerExtensions(t *testing.T) {
	s := rust.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".rs": true,
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
	s := rust.New()
	content := readFixture(t, "crypto_usage.rs")
	findings, err := s.ScanFile("crypto_usage.rs", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.rs, got none")
	}

	// ring::digest SHA-256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.RuleID == "cbom-rust-ring-digest" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "ring SHA-256 digest finding")

	// ring::digest SHA-1 (broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha1" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "ring SHA-1 digest finding with HIGH severity")

	// ring::aead AES-256-GCM
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "AES-256-GCM" &&
			f.Properties.Primitive == "ae" &&
			f.RuleID == "cbom-rust-ring-aead"
	}, "ring AES-256-GCM AEAD finding")

	// ring::aead ChaCha20-Poly1305
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "ChaCha20-Poly1305" &&
			f.Properties.AlgorithmFamily == "chacha20" &&
			f.RuleID == "cbom-rust-ring-aead"
	}, "ring ChaCha20-Poly1305 AEAD finding")

	// ring::agreement X25519
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "X25519" &&
			f.Properties.AlgorithmFamily == "x25519" &&
			f.Properties.Primitive == "key-agree" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "ring X25519 key agreement finding")

	// ring::agreement ECDH P-256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "ECDH-P256" &&
			f.Properties.AlgorithmFamily == "ecdh" &&
			f.Properties.Primitive == "key-agree" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "ring ECDH P-256 key agreement finding")

	// ring::pbkdf2
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.Properties.Primitive == "kdf" &&
			f.RuleID == "cbom-rust-ring-pbkdf2"
	}, "ring PBKDF2 key derivation finding")

	// ring::signature Ed25519
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ed25519" &&
			f.Properties.Primitive == "signature" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "ring Ed25519 signature finding")

	// ring::signature ECDSA
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ecdsa" &&
			f.Properties.Primitive == "signature"
	}, "ring ECDSA signature finding")

	// ring::signature RSA
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.Primitive == "signature" &&
			f.RuleID == "cbom-rust-ring-signature"
	}, "ring RSA signature finding")

	// rustls ClientConfig
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetProtocol &&
			f.Properties.ProtocolType == "tls" &&
			f.RuleID == "cbom-rust-rustls-config"
	}, "rustls TLS config finding")

	// rustls cipher suites
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-rust-rustls-cipher-suite"
	}, "rustls cipher suite finding")

	// openssl crate RSA
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.RuleID == "cbom-rust-openssl-rsa"
	}, "openssl crate RSA finding")

	// openssl crate SHA-256 hash
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.RuleID == "cbom-rust-openssl-hash"
	}, "openssl crate SHA-256 hash finding")

	// openssl crate MD5 (broken, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh &&
			f.RuleID == "cbom-rust-openssl-hash"
	}, "openssl crate MD5 hash finding with HIGH severity")

	// openssl crate AES symmetric
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.RuleID == "cbom-rust-openssl-symm"
	}, "openssl crate AES symmetric finding")

	// openssl crate DES (broken, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh &&
			f.RuleID == "cbom-rust-openssl-symm"
	}, "openssl crate DES finding with HIGH severity")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	s := rust.New()

	t.Run("Ed25519 is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`fn f() { let kp = signature::Ed25519KeyPair::from_pkcs8(bytes).unwrap(); }`)
		findings, err := s.ScanFile("test.rs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "ed25519" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "Ed25519 finding with QuantumVulnerable status")
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		code := []byte(`fn f() { let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).unwrap(); }`)
		findings, err := s.ScanFile("test.rs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.QuantumStatus == types.QuantumSafe
		}, "AES finding with QuantumSafe status")
	})

	t.Run("SHA-1 is Broken", func(t *testing.T) {
		code := []byte(`fn f() { let h = digest::digest(&digest::SHA1, data); }`)
		findings, err := s.ScanFile("test.rs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "sha1" &&
				f.Properties.QuantumStatus == types.Broken
		}, "SHA-1 finding with Broken status")
	})

	t.Run("MD5 is Broken via openssl", func(t *testing.T) {
		code := []byte(`fn f() { let h = openssl::hash::Hasher::new(openssl::hash::MessageDigest::md5()).unwrap(); }`)
		findings, err := s.ScanFile("test.rs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "md5" &&
				f.Properties.QuantumStatus == types.Broken
		}, "MD5 finding with Broken status")
	})

	t.Run("X25519 is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`fn f() { let pk = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap(); }`)
		findings, err := s.ScanFile("test.rs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "x25519" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "X25519 finding with QuantumVulnerable status")
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := rust.New()
	findings, err := s.ScanFile("empty.rs", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCryptoRust(t *testing.T) {
	s := rust.New()
	code := []byte(`
fn main() {
    println!("Hello, World!");
    let x = 42;
}
`)
	findings, err := s.ScanFile("hello.rs", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := rust.New()
	content := readFixture(t, "crypto_usage.rs")
	findings, err := s.ScanFile("crypto_usage.rs", content)
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
	s := rust.New()
	content := readFixture(t, "crypto_usage.rs")
	findings, err := s.ScanFile("crypto_usage.rs", content)
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
