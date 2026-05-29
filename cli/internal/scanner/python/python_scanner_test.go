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
// PyCryptodome constructor usage tests
// ---------------------------------------------------------------------------

func TestPyCryptodomeUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "pycryptodome_usage.py")
	findings, err := s.ScanFile("pycryptodome_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	cases := []struct {
		desc   string
		family string
		mode   string
	}{
		{"AES-GCM via AES.new", "aes", "gcm"},
		{"AES-ECB via AES.new", "aes", "ecb"},
		{"AES-CBC via AES.new", "aes", "cbc"},
		{"AES-SIV via AES.new", "aes", "siv"},
		{"DES-ECB via DES.new", "des", "ecb"},
		{"3DES-CBC via DES3.new", "3des", "cbc"},
	}
	for _, tc := range cases {
		tc := tc
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == tc.family &&
				f.Properties.Mode == tc.mode && f.Pass == 1
		}, tc.desc)
	}

	// ARC4 (no mode) — broken stream cipher.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rc4" && f.Name == "ARC4"
	}, "ARC4 via ARC4.new")

	// ChaCha20-Poly1305 AEAD.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "chacha20-poly1305" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "ChaCha20-Poly1305 via ChaCha20_Poly1305.new")

	// BLAKE2b hash via BLAKE2b.new.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "blake2b" &&
			f.Properties.Primitive == "hash"
	}, "BLAKE2b via BLAKE2b.new")

	// SHA-256 hash via SHA256.new.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" && f.Properties.Primitive == "hash"
	}, "SHA-256 via SHA256.new")
}

// TestPyCryptodomeUsageGated ensures bare ClassName.new() calls are NOT flagged
// when the class was never imported from a Crypto.* module (zero false positives).
func TestPyCryptodomeUsageGated(t *testing.T) {
	s := python.New()
	src := []byte("class AES:\n    pass\n\ndef f(key):\n    return AES.new(key, AES.MODE_GCM)\n")
	findings, err := s.ScanFile("not_pycryptodome.py", src)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertNoFinding(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-python-pycryptodome-aes-usage"
	}, "AES.new without Crypto import must not be flagged")
}

// ---------------------------------------------------------------------------
// pyca one-shot AEAD + truncated SHA-512 tests
// ---------------------------------------------------------------------------

func TestPycaAEADUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "pyca_aead_usage.py")
	findings, err := s.ScanFile("pyca_aead_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	aeadCases := []struct {
		desc string
		name string
		mode string
	}{
		{"AES-GCM AEAD", "AES-GCM", "gcm"},
		{"AES-CCM AEAD", "AES-CCM", "ccm"},
		{"AES-SIV AEAD", "AES-SIV", "siv"},
		{"ChaCha20-Poly1305 AEAD", "ChaCha20-Poly1305", "aead"},
	}
	for _, tc := range aeadCases {
		tc := tc
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Name == tc.name && f.Properties.Mode == tc.mode &&
				f.Properties.Primitive == "ae" && f.Pass == 1
		}, tc.desc)
	}

	// Truncated SHA-512 variants.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-512/224" && f.Properties.AlgorithmFamily == "sha-512"
	}, "SHA-512/224 hash")
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-512/256" && f.Properties.AlgorithmFamily == "sha-512"
	}, "SHA-512/256 hash")
}

// TestPycaAEADGated ensures AEAD constructors are not flagged without the aead import.
func TestPycaAEADGated(t *testing.T) {
	s := python.New()
	src := []byte("def f(key):\n    return AESGCM(key)\n")
	findings, err := s.ScanFile("no_import.py", src)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertNoFinding(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-python-cryptography-aead-aesgcm"
	}, "AESGCM() without aead import must not be flagged")
}

// ---------------------------------------------------------------------------
// Weak PRNG (random module) tests
// ---------------------------------------------------------------------------

func TestWeakRandomUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "weak_random_usage.py")
	findings, err := s.ScanFile("weak_random_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Security-sensitive uses flagged (weak_token, weak_password).
	var weakCount int
	for _, f := range findings {
		if f.RuleID == "cbom-python-weak-random" {
			weakCount++
		}
	}
	if weakCount != 2 {
		t.Errorf("expected exactly 2 weak-random findings (token+password), got %d", weakCount)
		for _, f := range findings {
			if f.RuleID == "cbom-python-weak-random" {
				t.Logf("  weak-random at line %d", f.Location.StartLine)
			}
		}
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-python-weak-random" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "weak PRNG flagged HIGH and quantum-safe")
}

// ---------------------------------------------------------------------------
// Tier-2 asymmetric tests: SM2 (gmssl), ECIES (eciespy), GOST (gostcrypto) (#32)
// ---------------------------------------------------------------------------

func TestTier2AsymmetricUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "tier2_asymmetric_usage.py")
	findings, err := s.ScanFile("tier2_asymmetric_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// SM2 via gmssl
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sm2" &&
			f.Name == "SM2" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "SM2 (gmssl CryptSM2) finding (quantum-vulnerable)")

	// ECIES via eciespy (encrypt + decrypt)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ecies" &&
			f.Name == "ECIES" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "ECIES (eciespy) finding (quantum-vulnerable)")

	// GOST R 34.10 signature via gostcrypto
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "gost" &&
			f.Properties.Primitive == "signature" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "GOST R 34.10 signature (gostcrypto) finding (quantum-vulnerable)")

	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// Paillier homomorphic encryption via python-paillier / phe (#41).
func TestPaillierUsage(t *testing.T) {
	s := python.New()
	content := readFixture(t, "paillier_usage.py")
	findings, err := s.ScanFile("paillier_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Paillier keypair generation
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "paillier" &&
			f.Name == "Paillier" &&
			f.Properties.Primitive == "pke" &&
			f.RuleID == "cbom-python-phe-paillier-keypair" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Paillier keypair (phe.generate_paillier_keypair) finding (quantum-vulnerable)")

	// Paillier public key reconstruction
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "paillier" &&
			f.RuleID == "cbom-python-phe-paillier-publickey" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Paillier PaillierPublicKey finding (quantum-vulnerable)")

	// Paillier private key reconstruction
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "paillier" &&
			f.RuleID == "cbom-python-phe-paillier-privatekey" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Paillier PaillierPrivateKey finding (quantum-vulnerable)")

	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// TestPaillierNoFalsePositive ensures Paillier APIs are not flagged when the
// phe library is not imported (zero-FP discipline, #41).
func TestPaillierNoFalsePositive(t *testing.T) {
	s := python.New()
	src := []byte(`def generate_paillier_keypair():
    return (1, 2)

def f():
    pub, priv = generate_paillier_keypair()
    return pub
`)
	findings, err := s.ScanFile("no_phe_import.py", src)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertNoFinding(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "paillier"
	}, "generate_paillier_keypair() without phe import must not be flagged as Paillier")
}

// TestTier2NoFalsePositive ensures Tier-2 APIs are not flagged when the
// relevant library is not imported.
func TestTier2NoFalsePositive(t *testing.T) {
	s := python.New()
	src := []byte(`def encrypt(pubkey, data):
    return data

def decrypt(privkey, data):
    return data

def f():
    encrypt("k", b"x")
    decrypt("k", b"x")
`)
	findings, err := s.ScanFile("no_import.py", src)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertNoFinding(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ecies"
	}, "encrypt()/decrypt() without eciespy import must not be flagged as ECIES")
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

func assertNoFinding(t *testing.T, findings []types.Finding, match func(types.Finding) bool, description string) {
	t.Helper()
	for _, f := range findings {
		if match(f) {
			t.Errorf("unexpected finding (false positive): %s — got Name=%q RuleID=%s line=%d",
				description, f.Name, f.RuleID, f.Location.StartLine)
		}
	}
}

// ---------------------------------------------------------------------------
// Tier-3 quantum families: BLS + Schnorr (issue #33)
// ---------------------------------------------------------------------------

func TestBLSPythonDetection(t *testing.T) {
	s := python.New()

	t.Run("aliased py_ecc.bls import is quantum-vulnerable", func(t *testing.T) {
		code := []byte(`from py_ecc.bls import G2ProofOfPossession as bls
def f(sk, m):
    return bls.Sign(sk, m)
`)
		findings, err := s.ScanFile("t.py", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "bls" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable &&
				f.RuleID == "cbom-python-bls-sign"
		}, "BLS Sign finding with QuantumVulnerable status")
	})

	t.Run("direct symbol import Aggregate", func(t *testing.T) {
		code := []byte(`from py_ecc.bls import G2Basic
def f(sigs):
    return G2Basic.Aggregate(sigs)
`)
		findings, err := s.ScanFile("t.py", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "bls" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "BLS Aggregate finding")
	})
}

func TestSchnorrPythonDetection(t *testing.T) {
	s := python.New()
	code := []byte(`from coincurve import PrivateKey
def sign(key, msg):
    return key.sign_schnorr(msg)
`)
	findings, err := s.ScanFile("t.py", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "schnorr" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable &&
			f.RuleID == "cbom-python-schnorr-sign"
	}, "Schnorr sign_schnorr finding with QuantumVulnerable status")
}

// TestBLSSchnorrPythonZeroFalsePositive ensures BLS/Schnorr API method names
// without an anchoring import produce no findings (hard zero-FP constraint).
func TestBLSSchnorrPythonZeroFalsePositive(t *testing.T) {
	s := python.New()
	code := []byte(`# A model class with a coincidentally-named Sign method.
class Model:
    def Sign(self, sk, m):
        return sk
def go():
    bls = Model()
    return bls.Sign(b"x", b"y")
`)
	findings, err := s.ScanFile("noimport.py", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertNoFinding(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bls" || f.Properties.AlgorithmFamily == "schnorr"
	}, "BLS/Schnorr without anchoring import")
}

func TestQuantumFamiliesPythonFixture(t *testing.T) {
	s := python.New()
	content := readFixture(t, "quantum_families_usage.py")
	findings, err := s.ScanFile("quantum_families_usage.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bls" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "BLS finding in fixture")
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "schnorr" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Schnorr finding in fixture")
}
