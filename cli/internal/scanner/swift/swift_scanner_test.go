package swift_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/swift"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/swift/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/swift/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "swift")
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

func TestSwiftScannerName(t *testing.T) {
	s := swift.New()
	if s.Name() != "swift" {
		t.Errorf("expected Name() = %q, got %q", "swift", s.Name())
	}
}

func TestSwiftScannerExtensions(t *testing.T) {
	s := swift.New()
	exts := s.Extensions()
	expected := map[string]bool{".swift": true}
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
	s := swift.New()
	content := readFixture(t, "crypto_usage.swift")
	findings, err := s.ScanFile("crypto_usage.swift", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.swift, got none")
	}

	// AES-GCM via CryptoKit
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "AES-GCM" &&
			f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "ae" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "AES-GCM finding with QuantumSafe status")

	// ChaChaPoly via CryptoKit
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "ChaChaPoly" &&
			f.Properties.AlgorithmFamily == "chacha20" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "ChaChaPoly finding with QuantumSafe status")

	// SHA-256 via CryptoKit
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" &&
			f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash"
	}, "SHA-256 finding")

	// HMAC-SHA256 via CryptoKit
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HMAC-SHA256" &&
			f.Properties.Primitive == "mac"
	}, "HMAC-SHA256 finding")

	// P256 signing (ECDSA, quantum-vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "P256-Signing" &&
			f.Properties.AlgorithmFamily == "ecdsa" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "P256-Signing with QuantumVulnerable status")

	// Curve25519 signing (Ed25519, quantum-vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "Curve25519-Signing" &&
			f.Properties.AlgorithmFamily == "ed25519" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Curve25519-Signing with QuantumVulnerable status")

	// CC_SHA1 (broken, high severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CC_SHA1" &&
			f.Properties.AlgorithmFamily == "sha1" &&
			f.Severity == types.SeverityHigh
	}, "CC_SHA1 with HIGH severity")

	// CC_MD5 (broken, high severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CC_MD5" &&
			f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh
	}, "CC_MD5 with HIGH severity")

	// CCKeyDerivationPBKDF
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CCKeyDerivationPBKDF" &&
			f.Properties.Primitive == "kdf"
	}, "CCKeyDerivationPBKDF finding")

	// SecKeyCreateRandomKey
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SecKeyCreateRandomKey" &&
			f.AssetType == types.AssetRelatedCryptoMaterial
	}, "SecKeyCreateRandomKey finding")

	// SecCertificate
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SecCertificate" &&
			f.AssetType == types.AssetCertificate
	}, "SecCertificate finding")

	// SymmetricKey
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SymmetricKey" &&
			f.AssetType == types.AssetRelatedCryptoMaterial
	}, "SymmetricKey finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// CCCrypt algorithm-argument inspection
// ---------------------------------------------------------------------------

func TestCCCryptAlgorithmInspection(t *testing.T) {
	cases := []struct {
		name      string
		constant  string
		findName  string
		family    string
		severity  types.Severity
		primitive string
	}{
		{"DES", "kCCAlgorithmDES", "CCCrypt-DES", "des", types.SeverityHigh, "block-cipher"},
		{"3DES", "kCCAlgorithm3DES", "CCCrypt-3DES", "3des", types.SeverityHigh, "block-cipher"},
		{"RC4", "kCCAlgorithmRC4", "CCCrypt-RC4", "rc4", types.SeverityHigh, "stream-cipher"},
		{"AES", "kCCAlgorithmAES", "CCCrypt-AES", "aes", types.SeverityInfo, "block-cipher"},
		{"Blowfish", "kCCAlgorithmBlowfish", "CCCrypt-Blowfish", "blowfish", types.SeverityHigh, "block-cipher"},
		{"CAST", "kCCAlgorithmCAST", "CCCrypt-CAST", "cast5", types.SeverityHigh, "block-cipher"},
	}
	s := swift.New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := []byte("import CommonCrypto\nCCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(" + tc.constant + "), 0, key, keyLen, nil, data, dataLen, out, outLen, &moved)\n")
			findings, err := s.ScanFile("t.swift", code)
			if err != nil {
				t.Fatalf("ScanFile failed: %v", err)
			}
			// Exactly one CCCrypt-derived finding, and it is the specific one
			// (no generic "CCCrypt" duplicate).
			ccCount := 0
			for _, f := range findings {
				if f.Name == "CCCrypt" {
					t.Errorf("generic CCCrypt finding should not be emitted alongside %s", tc.findName)
				}
				if f.RuleID != "" && len(f.RuleID) >= len("cbom-swift-commoncrypto-cccrypt") &&
					f.RuleID[:len("cbom-swift-commoncrypto-cccrypt")] == "cbom-swift-commoncrypto-cccrypt" {
					ccCount++
				}
			}
			if ccCount != 1 {
				t.Errorf("expected exactly 1 CCCrypt finding, got %d", ccCount)
			}
			assertFindingExists(t, findings, func(f types.Finding) bool {
				return f.Name == tc.findName &&
					f.Properties.AlgorithmFamily == tc.family &&
					f.Properties.Primitive == tc.primitive &&
					f.Severity == tc.severity
			}, tc.findName+" finding")
		})
	}
}

func TestCCCryptGenericFallback(t *testing.T) {
	// CCCrypt with no recognized kCCAlgorithm* constant (e.g. variable) keeps
	// the generic finding.
	code := []byte("import CommonCrypto\nCCCrypt(op, algo, 0, key, keyLen, nil, data, dataLen, out, outLen, &moved)\n")
	s := swift.New()
	findings, err := s.ScanFile("t.swift", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CCCrypt" && f.RuleID == "cbom-swift-commoncrypto-cccrypt"
	}, "generic CCCrypt fallback finding")
}

func TestCCCryptFixtureDESandRC4(t *testing.T) {
	s := swift.New()
	content := readFixture(t, "crypto_usage.swift")
	findings, err := s.ScanFile("crypto_usage.swift", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CCCrypt-DES" && f.Severity == types.SeverityHigh
	}, "CCCrypt-DES finding")
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CCCrypt-RC4" && f.Severity == types.SeverityHigh
	}, "CCCrypt-RC4 finding")
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "CCCrypt-AES"
	}, "CCCrypt-AES finding")
}

// ---------------------------------------------------------------------------
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropagation(t *testing.T) {
	t.Run("direct constprop API", func(t *testing.T) {
		cp := swift.NewConstPropagator()
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
		cp := swift.NewConstPropagator()
		_, ok := cp.Resolve("nonexistent")
		if ok {
			t.Error("expected Resolve for nonexistent variable to return false")
		}
	})

	t.Run("let assignment", func(t *testing.T) {
		cp := swift.NewConstPropagator()
		cp.CollectAssignments([]byte(`let algo = "AES-256"
let keySize = 256`))
		val, ok := cp.Resolve("algo")
		if !ok || val != "AES-256" {
			t.Errorf("expected algo=%q, got %q (ok=%v)", "AES-256", val, ok)
		}
		val, ok = cp.Resolve("keySize")
		if !ok || val != "256" {
			t.Errorf("expected keySize=%q, got %q (ok=%v)", "256", val, ok)
		}
	})
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	t.Run("ECDSA is QuantumVulnerable", func(t *testing.T) {
		qi := swift.GetQuantumInfo("ecdsa")
		if qi.Status != types.QuantumVulnerable {
			t.Errorf("expected QuantumVulnerable, got %s", qi.Status)
		}
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		qi := swift.GetQuantumInfo("aes")
		if qi.Status != types.QuantumSafe {
			t.Errorf("expected QuantumSafe, got %s", qi.Status)
		}
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		qi := swift.GetQuantumInfo("md5")
		if qi.Status != types.Broken {
			t.Errorf("expected Broken, got %s", qi.Status)
		}
	})

	t.Run("unknown algo returns QuantumUnknown", func(t *testing.T) {
		qi := swift.GetQuantumInfo("totally-made-up-algo")
		if qi.Status != types.QuantumUnknown {
			t.Errorf("expected QuantumUnknown, got %s", qi.Status)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := swift.New()
	findings, err := s.ScanFile("empty.swift", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCrypto(t *testing.T) {
	s := swift.New()
	code := []byte(`
import Foundation

func hello() {
    print("Hello, world!")
    let x = 42
}

hello()
`)
	findings, err := s.ScanFile("no_crypto.swift", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := swift.New()
	content := readFixture(t, "crypto_usage.swift")
	findings, err := s.ScanFile("crypto_usage.swift", content)
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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Primitive=%s QS=%s Pass=%d Asset=%s",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass, f.AssetType)
	}
}
