package golang_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/golang"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/golang/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/golang/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "golang")
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

func TestGoScannerName(t *testing.T) {
	s := golang.New()
	if s.Name() != "go" {
		t.Errorf("expected Name() = %q, got %q", "go", s.Name())
	}
}

func TestGoScannerExtensions(t *testing.T) {
	s := golang.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".go": true,
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
// crypto/* stdlib tests
// ---------------------------------------------------------------------------

func TestCryptoUsage(t *testing.T) {
	s := golang.New()
	content := readFixture(t, "crypto_usage.go")
	findings, err := s.ScanFile("crypto_usage.go", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.go, got none")
	}

	// AES block cipher via aes.NewCipher
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher" &&
			f.Severity == types.SeverityInfo
	}, "AES block cipher finding via aes.NewCipher")

	// AES-GCM via cipher.NewGCM
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm" &&
			f.Properties.Primitive == "ae" &&
			f.Severity == types.SeverityInfo
	}, "AES-GCM finding via cipher.NewGCM")

	// DES (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "DES finding with HIGH severity and Broken quantum status")

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

	// SHA-256 (good, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 hash finding with INFO severity and QuantumSafe status")

	// RSA-2048 (quantum-vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 2048 &&
			f.Properties.QuantumStatus == types.QuantumVulnerable &&
			f.Name == "RSA-2048"
	}, "RSA-2048 key generation finding with QuantumVulnerable status")

	// TLS 1.2 (good, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLS 1.2" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.ProtocolVersion == "1.2"
	}, "TLS 1.2 finding with INFO severity")

	// TLS 1.0 (deprecated, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLS 1.0" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.ProtocolVersion == "1.0"
	}, "TLS 1.0 finding with HIGH severity")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// golang.org/x/crypto tests
// ---------------------------------------------------------------------------

func TestXCryptoUsage(t *testing.T) {
	s := golang.New()
	content := readFixture(t, "xcrypto_usage.go")
	findings, err := s.ScanFile("xcrypto_usage.go", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from xcrypto_usage.go, got none")
	}

	// bcrypt
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bcrypt" &&
			f.Properties.Primitive == "kdf"
	}, "bcrypt password hashing finding")

	// Argon2
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "argon2" &&
			f.Properties.Primitive == "kdf"
	}, "Argon2 key derivation finding")

	// ChaCha20-Poly1305
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "chacha20" &&
			f.Properties.Primitive == "ae" &&
			f.Name == "ChaCha20-Poly1305"
	}, "ChaCha20-Poly1305 AEAD finding")

	// scrypt
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "scrypt" &&
			f.Properties.Primitive == "kdf"
	}, "scrypt key derivation finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// tjfoc/gmsm SM2 tests (#32)
// ---------------------------------------------------------------------------

func TestSM2Usage(t *testing.T) {
	s := golang.New()
	content := readFixture(t, "sm2_usage.go")
	findings, err := s.ScanFile("sm2_usage.go", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected SM2 findings from sm2_usage.go, got none")
	}

	// SM2 key generation (pke, quantum-vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sm2" &&
			f.Name == "SM2" &&
			f.Properties.Primitive == "pke" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "SM2 GenerateKey finding (quantum-vulnerable)")

	// SM2 signature
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sm2" &&
			f.Properties.Primitive == "signature" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "SM2 Sign finding (quantum-vulnerable)")

	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// TestSM2NoFalsePositive ensures SM2 function names are not flagged when the
// gmsm/sm2 package is not imported.
func TestSM2NoFalsePositive(t *testing.T) {
	s := golang.New()
	code := []byte(`package main

type sm2 struct{}

func (sm2) Sign(msg []byte) {}
func (sm2) Encrypt(data []byte) {}

func f() {
	var x sm2
	x.Sign(nil)
	x.Encrypt(nil)
}
`)
	findings, err := s.ScanFile("nofp.go", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "sm2" {
			t.Errorf("false positive: SM2 flagged without gmsm import (%s)", f.RuleID)
		}
	}
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	s := golang.New()

	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`package main
import "crypto/rsa"
import "crypto/rand"
func f() { rsa.GenerateKey(rand.Reader, 2048) }
`)
		findings, err := s.ScanFile("test.go", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rsa" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "RSA finding with QuantumVulnerable status")
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		code := []byte(`package main
import "crypto/aes"
func f() { aes.NewCipher(nil) }
`)
		findings, err := s.ScanFile("test.go", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.QuantumStatus == types.QuantumSafe
		}, "AES finding with QuantumSafe status")
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		code := []byte(`package main
import "crypto/md5"
func f() { md5.New() }
`)
		findings, err := s.ScanFile("test.go", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "md5" &&
				f.Properties.QuantumStatus == types.Broken
		}, "MD5 finding with Broken status")
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := golang.New()
	findings, err := s.ScanFile("empty.go", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCryptoGo(t *testing.T) {
	s := golang.New()
	code := []byte(`package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
	x := 42
	_ = x
}
`)
	findings, err := s.ScanFile("hello.go", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := golang.New()
	content := readFixture(t, "crypto_usage.go")
	findings, err := s.ScanFile("crypto_usage.go", content)
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
	s := golang.New()
	content := readFixture(t, "crypto_usage.go")
	findings, err := s.ScanFile("crypto_usage.go", content)
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
