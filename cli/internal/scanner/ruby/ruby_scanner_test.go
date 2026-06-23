package ruby_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/ruby"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/ruby/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/ruby/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "ruby")
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

func TestRubyScannerName(t *testing.T) {
	s := ruby.New()
	if s.Name() != "ruby" {
		t.Errorf("expected Name() = %q, got %q", "ruby", s.Name())
	}
}

func TestRubyScannerExtensions(t *testing.T) {
	s := ruby.New()
	exts := s.Extensions()
	expected := map[string]bool{".rb": true}
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
// Fixture tests
// ---------------------------------------------------------------------------

func TestCryptoUsage(t *testing.T) {
	s := ruby.New()
	content := readFixture(t, "crypto_usage.rb")
	findings, err := s.ScanFile("crypto_usage.rb", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.rb, got none")
	}

	// AES-256-CBC via OpenSSL::Cipher
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "AES-256-CBC finding with QuantumSafe status")

	// DES-CBC (should be HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh
	}, "DES-CBC finding with HIGH severity")

	// RC4 (should be HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rc4" &&
			f.Severity == types.SeverityHigh
	}, "RC4 finding with HIGH severity")

	// SHA-256 via OpenSSL::Digest
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash"
	}, "SHA-256 OpenSSL::Digest finding")

	// SHA-1 (broken, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha1" &&
			f.Severity == types.SeverityHigh &&
			f.RuleID == "cbom-ruby-openssl-digest-sha1"
	}, "SHA-1 OpenSSL::Digest with HIGH severity")

	// MD5 (broken, HIGH) via OpenSSL::Digest
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.Primitive == "hash"
	}, "MD5 finding with HIGH severity")

	// RSA-2048 via OpenSSL::PKey
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 2048 &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA-2048 finding with QuantumVulnerable status")

	// EC via OpenSSL::PKey
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ec" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "EC finding with QuantumVulnerable status")

	// OpenSSL::SSL::SSLContext
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetProtocol &&
			f.Properties.ProtocolType == "tls"
	}, "TLS protocol finding")

	// BCrypt
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bcrypt" &&
			f.Properties.Primitive == "kdf"
	}, "BCrypt finding")

	// Digest::SHA256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-ruby-digest-sha-256" &&
			f.Properties.AlgorithmFamily == "sha-256"
	}, "Digest::SHA256 finding")

	// Digest::MD5 (HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-ruby-digest-md5" &&
			f.Severity == types.SeverityHigh
	}, "Digest::MD5 with HIGH severity")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropagation(t *testing.T) {
	t.Run("direct constprop API", func(t *testing.T) {
		cp := ruby.NewConstPropagator()
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
		cp := ruby.NewConstPropagator()
		_, ok := cp.Resolve("nonexistent")
		if ok {
			t.Error("expected Resolve for nonexistent variable to return false")
		}
	})
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		qi := ruby.GetQuantumInfo("rsa")
		if qi.Status != types.QuantumVulnerable {
			t.Errorf("expected QuantumVulnerable, got %s", qi.Status)
		}
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		qi := ruby.GetQuantumInfo("aes")
		if qi.Status != types.QuantumSafe {
			t.Errorf("expected QuantumSafe, got %s", qi.Status)
		}
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		qi := ruby.GetQuantumInfo("md5")
		if qi.Status != types.Broken {
			t.Errorf("expected Broken, got %s", qi.Status)
		}
	})

	t.Run("unknown algo returns QuantumUnknown", func(t *testing.T) {
		qi := ruby.GetQuantumInfo("totally-made-up-algo")
		if qi.Status != types.QuantumUnknown {
			t.Errorf("expected QuantumUnknown, got %s", qi.Status)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := ruby.New()
	findings, err := s.ScanFile("empty.rb", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCrypto(t *testing.T) {
	s := ruby.New()
	code := []byte(`
def hello
  puts "Hello, world!"
  x = 42
  x
end

hello
`)
	findings, err := s.ScanFile("no_crypto.rb", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestOpenSSLPkeyDSANew(t *testing.T) {
	s := ruby.New()
	code := []byte(`key = OpenSSL::PKey::DSA.new(2048)`)
	findings, err := s.ScanFile("dsa.rb", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "dsa" && f.Properties.KeySize == 2048
	}, "DSA-2048 via OpenSSL::PKey::DSA.new")
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := ruby.New()
	content := readFixture(t, "crypto_usage.rb")
	findings, err := s.ScanFile("crypto_usage.rb", content)
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
