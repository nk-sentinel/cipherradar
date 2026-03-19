package kotlin_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kotlin"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/kotlin/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/kotlin/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "kotlin")
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

func TestKotlinScannerName(t *testing.T) {
	s := kotlin.New()
	if s.Name() != "kotlin" {
		t.Errorf("expected Name() = %q, got %q", "kotlin", s.Name())
	}
}

func TestKotlinScannerExtensions(t *testing.T) {
	s := kotlin.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".kt":  true,
		".kts": true,
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
// CryptoUsage.kt tests
// ---------------------------------------------------------------------------

func TestCryptoUsage(t *testing.T) {
	s := kotlin.New()
	content := readFixture(t, "CryptoUsage.kt")
	findings, err := s.ScanFile("CryptoUsage.kt", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from CryptoUsage.kt, got none")
	}

	// AES-GCM (good, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm" &&
			f.Severity == types.SeverityInfo
	}, "AES/GCM finding with INFO severity")

	// DES/ECB (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Properties.Mode == "ecb" &&
			f.Severity == types.SeverityHigh
	}, "DES/ECB finding with HIGH severity")

	// MD5 (broken hash, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "MD5 hash finding with HIGH severity and Broken quantum status")

	// SHA-256 (good hash, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 hash finding with INFO severity and QuantumSafe status")

	// RSA key pair (quantum vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA key pair finding with QuantumVulnerable status")

	// HMAC
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "mac" &&
			f.Properties.AlgorithmFamily == "hmac" &&
			f.Name == "HmacSHA256"
	}, "HmacSHA256 MAC finding")

	// TLSv1.2 (good, INFO)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLSv1.2" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.ProtocolVersion == "1.2"
	}, "TLSv1.2 finding with INFO severity")

	// TLSv1.0 (deprecated, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLSv1.0" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.ProtocolVersion == "1.0"
	}, "TLSv1.0 finding with HIGH severity")

	// Constant propagation: AES/CBC resolved from const val ALGORITHM
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc" &&
			f.Confidence == types.ConfidenceMedium
	}, "AES/CBC finding via constant propagation with medium confidence")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}

	// All rule IDs must start with cbom-kotlin-
	for _, f := range findings {
		if f.RuleID != "" && !hasPrefix(f.RuleID, "cbom-kotlin-") {
			t.Errorf("finding %s has RuleID=%q, expected prefix cbom-kotlin-", f.ID, f.RuleID)
		}
	}
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	s := kotlin.New()

	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`class T { void f() throws Exception { KeyPairGenerator.getInstance("RSA"); } }`)
		findings, err := s.ScanFile("test.kt", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rsa" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "RSA finding with QuantumVulnerable status")
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		code := []byte(`class T { void f() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); } }`)
		findings, err := s.ScanFile("test.kt", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.QuantumStatus == types.QuantumSafe
		}, "AES finding with QuantumSafe status")
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		code := []byte(`class T { void f() throws Exception { MessageDigest.getInstance("MD5"); } }`)
		findings, err := s.ScanFile("test.kt", code)
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
	s := kotlin.New()
	findings, err := s.ScanFile("empty.kt", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCryptoKotlin(t *testing.T) {
	s := kotlin.New()
	code := []byte(`
fun main() {
    println("Hello, World!")
    val x = 42
    val s = "test"
}
`)
	findings, err := s.ScanFile("HelloWorld.kt", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := kotlin.New()
	content := readFixture(t, "CryptoUsage.kt")
	findings, err := s.ScanFile("CryptoUsage.kt", content)
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
	s := kotlin.New()
	content := readFixture(t, "CryptoUsage.kt")
	findings, err := s.ScanFile("CryptoUsage.kt", content)
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
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropagation(t *testing.T) {
	s := kotlin.New()

	t.Run("val declaration", func(t *testing.T) {
		// The Java grammar will parse this as Java code; the const prop
		// text scanner handles Kotlin-specific val/var patterns.
		code := []byte(`
const val MY_ALGO = "AES/CBC/PKCS5Padding"
class T {
    void f() throws Exception {
        Cipher.getInstance(MY_ALGO);
    }
}
`)
		findings, err := s.ScanFile("test.kt", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.Mode == "cbc" &&
				f.Confidence == types.ConfidenceMedium
		}, "AES/CBC finding via Kotlin const val propagation")
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Mode=%s Primitive=%s QS=%s Pass=%d AssetType=%s MaterialType=%s ProtocolVersion=%s",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass, f.AssetType, f.Properties.MaterialType,
			f.Properties.ProtocolVersion)
	}
}
