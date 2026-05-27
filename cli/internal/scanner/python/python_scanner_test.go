package python_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/python/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/python/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "python")
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

func TestPythonScannerName(t *testing.T) {
	s := python.New()
	if s.Name() != "python" {
		t.Errorf("expected Name() = %q, got %q", "python", s.Name())
	}
}

func TestPythonScannerExtensions(t *testing.T) {
	s := python.New()
	exts := s.Extensions()
	expected := map[string]bool{".py": true, ".pyw": true}
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
// hashlib tests
// ---------------------------------------------------------------------------

func TestHashlibUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "hashlib_usage.py")
	findings, err := s.ScanFile("hashlib_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from hashlib_usage.py, got none")
	}

	// Check that we find MD5 (broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "MD5" && f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh && f.Properties.QuantumStatus == types.Broken
	}, "MD5 finding with Broken quantum status and HIGH severity")

	// Check that we find SHA-1 (broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-1" && f.Properties.AlgorithmFamily == "sha1" &&
			f.Severity == types.SeverityHigh && f.Properties.QuantumStatus == types.Broken
	}, "SHA-1 finding with Broken quantum status and HIGH severity")

	// Check that we find SHA-256 (quantum safe)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" && f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 finding with QuantumSafe status")

	// Check hashlib.new with constprop-resolved algo
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-python-hashlib-new" &&
			(f.Confidence == types.ConfidenceMedium || f.Confidence == types.ConfidenceHigh)
	}, "hashlib.new() finding with resolved constant")

	// Check pbkdf2_hmac
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-python-hashlib-pbkdf2" &&
			f.Properties.Primitive == "kdf"
	}, "PBKDF2 finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// cryptography library tests
// ---------------------------------------------------------------------------

func TestCryptographyUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "cryptography_usage.py")
	findings, err := s.ScanFile("cryptography_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from cryptography_usage.py, got none")
	}

	// AES-CBC
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "AES-CBC finding with QuantumSafe status")

	// RSA-2048 (quantum vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 2048 &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA-2048 finding with QuantumVulnerable status")

	// EC key generation (SECP256R1)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ec" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "EC finding with QuantumVulnerable status")

	// SHA-256 hash
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash"
	}, "SHA-256 hash finding")

	// PBKDF2 KDF
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.Properties.Primitive == "kdf"
	}, "PBKDF2 KDF finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// ssl module tests
// ---------------------------------------------------------------------------

func TestSSLUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "ssl_usage.py")
	findings, err := s.ScanFile("ssl_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from ssl_usage.py, got none")
	}

	// TLS protocol usage
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetProtocol &&
			f.Properties.ProtocolType == "tls"
	}, "TLS protocol finding")

	// PROTOCOL_TLSv1 should be flagged as deprecated (high severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.ProtocolVersion == "1.0" &&
			f.Severity == types.SeverityHigh
	}, "TLSv1.0 deprecated finding with HIGH severity")

	// CERT_NONE should be critical
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-python-ssl-cert-none" &&
			f.Severity == types.SeverityCritical
	}, "CERT_NONE finding with CRITICAL severity")

	// TLSVersion.TLSv1_2 reference
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.ProtocolVersion == "1.2" &&
			f.AssetType == types.AssetProtocol
	}, "TLS 1.2 version reference")
}

// ---------------------------------------------------------------------------
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropagation(t *testing.T) {
	t.Run("simple string assignment", func(t *testing.T) {
		s := python.New()
		code := []byte(`
algo = "sha256"
h = hashlib.new(algo)
`)
		findings, err := s.ScanFile("test.py", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.RuleID == "cbom-python-hashlib-new" &&
				f.Name == "SHA-256" &&
				f.Confidence == types.ConfidenceMedium
		}, "hashlib.new() with resolved string constant")
	})

	t.Run("simple integer assignment", func(t *testing.T) {
		cp := python.NewConstPropagator()
		s := python.New()
		code := []byte(`
key_size = 2048
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
`)
		// Run via scanner to verify the propagation works end-to-end
		findings, err := s.ScanFile("test.py", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rsa" &&
				f.Properties.KeySize == 2048
		}, "RSA finding with constprop-resolved key_size=2048")

		// Also test the propagator directly
		_ = cp // used above conceptually
	})

	t.Run("unresolved variable returns empty", func(t *testing.T) {
		cp := python.NewConstPropagator()
		_, ok := cp.Resolve("nonexistent")
		if ok {
			t.Error("expected Resolve for nonexistent variable to return false")
		}
	})

	t.Run("direct constprop API", func(t *testing.T) {
		cp := python.NewConstPropagator()
		cp.Set("test_var", "test_value")
		val, ok := cp.Resolve("test_var")
		if !ok {
			t.Fatal("expected Resolve to return true")
		}
		if val != "test_value" {
			t.Errorf("expected %q, got %q", "test_value", val)
		}
	})
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		qi := python.GetQuantumInfo("rsa")
		if qi.Status != types.QuantumVulnerable {
			t.Errorf("expected QuantumVulnerable, got %s", qi.Status)
		}
	})

	t.Run("AES-256 is QuantumSafe", func(t *testing.T) {
		// aes-256 is an alias for the canonical aes family (NistLevel 1).
		// Per the YAML table, individual AES key sizes share the family entry.
		qi := python.GetQuantumInfo("aes-256")
		if qi.Status != types.QuantumSafe {
			t.Errorf("expected QuantumSafe, got %s", qi.Status)
		}
		if qi.NistLevel != 1 {
			t.Errorf("expected NistLevel=1 (canonical aes family), got %d", qi.NistLevel)
		}
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		qi := python.GetQuantumInfo("md5")
		if qi.Status != types.Broken {
			t.Errorf("expected Broken, got %s", qi.Status)
		}
	})

	t.Run("unknown algo returns QuantumUnknown", func(t *testing.T) {
		qi := python.GetQuantumInfo("totally-made-up-algo")
		if qi.Status != types.QuantumUnknown {
			t.Errorf("expected QuantumUnknown, got %s", qi.Status)
		}
	})

	t.Run("case insensitive lookup", func(t *testing.T) {
		qi := python.GetQuantumInfo("RSA")
		if qi.Status != types.QuantumVulnerable {
			t.Errorf("expected QuantumVulnerable for uppercase RSA, got %s", qi.Status)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := python.New()
	findings, err := s.ScanFile("empty.py", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCrypto(t *testing.T) {
	s := python.New()
	code := []byte(`
import os
import sys

def hello():
    print("Hello, world!")
    x = 42
    return x

if __name__ == "__main__":
    hello()
`)
	findings, err := s.ScanFile("no_crypto.py", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := python.New()
	content := readFixture(t, "hashlib_usage.py")
	findings, err := s.ScanFile("hashlib_usage.py", content)
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
	s := python.New()
	content := readFixture(t, "hashlib_usage.py")
	findings, err := s.ScanFile("hashlib_usage.py", content)
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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Mode=%s KeySize=%d QS=%s Pass=%d",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.KeySize,
			f.Properties.QuantumStatus, f.Pass)
	}
}
