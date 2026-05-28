package javascript_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/javascript"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/javascript/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/javascript/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "javascript")
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

func TestJSScannerName(t *testing.T) {
	s := javascript.New()
	if s.Name() != "javascript" {
		t.Errorf("expected Name() = %q, got %q", "javascript", s.Name())
	}
}

func TestJSScannerExtensions(t *testing.T) {
	s := javascript.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".js":  true,
		".jsx": true,
		".ts":  true,
		".tsx": true,
		".mjs": true,
		".cjs": true,
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
// Node.js crypto module tests
// ---------------------------------------------------------------------------

func TestCryptoUsage(t *testing.T) {
	s := javascript.New()
	content := readFixture(t, "crypto_usage.js")
	findings, err := s.ScanFile("crypto_usage.js", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.js, got none")
	}

	// MD5 (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "MD5" && f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh && f.Properties.QuantumStatus == types.Broken
	}, "MD5 finding with Broken quantum status and HIGH severity")

	// SHA-256 (quantum safe)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" && f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 finding with QuantumSafe status")

	// DES (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "DES" && f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh && f.Properties.QuantumStatus == types.Broken
	}, "DES finding with Broken quantum status and HIGH severity")

	// AES-256-GCM (quantum safe)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "AES-256-GCM" && f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm" && f.Properties.KeySize == 256
	}, "AES-256-GCM finding")

	// RSA-2048 (quantum vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "RSA-2048" && f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 2048 &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA-2048 finding with QuantumVulnerable status")

	// HMAC-SHA256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HMAC-SHA-256" && f.Properties.Primitive == "mac"
	}, "HMAC-SHA-256 finding")

	// PBKDF2
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.Properties.Primitive == "kdf"
	}, "PBKDF2 finding")

	// ECDH
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ecdh" &&
			f.Properties.Primitive == "key-agree"
	}, "ECDH finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// jsonwebtoken tests
// ---------------------------------------------------------------------------

func TestJWTUsage(t *testing.T) {
	s := javascript.New()
	content := readFixture(t, "jwt_usage.js")
	findings, err := s.ScanFile("jwt_usage.js", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from jwt_usage.js, got none")
	}

	// HS256 from jwt.sign
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HS256" && f.Properties.AlgorithmFamily == "jwt"
	}, "HS256 JWT signing finding")

	// alg:none (CRITICAL)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Severity == types.SeverityCritical &&
			f.Properties.AlgorithmFamily == "jwt"
	}, "JWT alg:none CRITICAL finding")

	// HS256 from jwt.verify algorithms array
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HS256" &&
			f.RuleID == "cbom-js-jwt-verify-hs256"
	}, "HS256 JWT verify finding")

	// HS384 from jwt.verify algorithms array
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HS384" &&
			f.RuleID == "cbom-js-jwt-verify-hs384"
	}, "HS384 JWT verify finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// node-forge tests
// ---------------------------------------------------------------------------

func TestForgeUsage(t *testing.T) {
	s := javascript.New()
	content := readFixture(t, "forge_usage.js")
	findings, err := s.ScanFile("forge_usage.js", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from forge_usage.js, got none")
	}

	// MD5 via forge.md.md5
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "MD5" && f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh
	}, "forge MD5 finding with HIGH severity")

	// SHA-256 via forge.md.sha256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" && f.Properties.AlgorithmFamily == "sha-256"
	}, "forge SHA-256 finding")

	// AES-CBC via forge.cipher.createCipher
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc"
	}, "forge AES-CBC finding")

	// RSA-2048 via forge.pki.rsa.generateKeyPair
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 2048 &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "forge RSA-2048 finding with QuantumVulnerable status")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// TypeScript tests
// ---------------------------------------------------------------------------

func TestTypescriptUsage(t *testing.T) {
	s := javascript.New()
	content := readFixture(t, "typescript_usage.ts")
	findings, err := s.ScanFile("typescript_usage.ts", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from typescript_usage.ts, got none")
	}

	// SHA-256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-256" && f.Properties.AlgorithmFamily == "sha-256" &&
			f.Confidence == types.ConfidenceHigh
	}, "TypeScript SHA-256 finding with HIGH confidence")

	// AES-256-CBC
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "AES-256-CBC" && f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc"
	}, "TypeScript AES-256-CBC finding")

	// Constprop-resolved SHA-384
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SHA-384" && f.Properties.AlgorithmFamily == "sha-384" &&
			f.Confidence == types.ConfidenceMedium
	}, "TypeScript constprop-resolved SHA-384 finding with MEDIUM confidence")

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
	t.Run("simple string assignment", func(t *testing.T) {
		s := javascript.New()
		code := []byte(`
const algo = 'sha256';
const h = crypto.createHash(algo);
`)
		findings, err := s.ScanFile("test.js", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Name == "SHA-256" &&
				f.Confidence == types.ConfidenceMedium
		}, "constprop-resolved SHA-256 with MEDIUM confidence")
	})

	t.Run("unresolved variable returns empty", func(t *testing.T) {
		cp := javascript.NewConstPropagator()
		_, ok := cp.Resolve("nonexistent")
		if ok {
			t.Error("expected Resolve for nonexistent variable to return false")
		}
	})

	t.Run("direct constprop API", func(t *testing.T) {
		cp := javascript.NewConstPropagator()
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
	s := javascript.New()

	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });`)
		findings, err := s.ScanFile("test.js", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rsa" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "RSA finding with QuantumVulnerable status")
	})

	t.Run("AES-256 is QuantumSafe", func(t *testing.T) {
		code := []byte(`const c = crypto.createCipheriv('aes-256-gcm', key, iv);`)
		findings, err := s.ScanFile("test.js", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.QuantumStatus == types.QuantumSafe
		}, "AES-256-GCM finding with QuantumSafe status")
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		code := []byte(`const h = crypto.createHash('md5');`)
		findings, err := s.ScanFile("test.js", code)
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
	s := javascript.New()
	findings, err := s.ScanFile("empty.js", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCrypto(t *testing.T) {
	s := javascript.New()
	code := []byte(`
const express = require('express');
const app = express();

function hello() {
    console.log("Hello, world!");
    const x = 42;
    return x;
}

app.get('/', (req, res) => {
    res.send(hello());
});
`)
	findings, err := s.ScanFile("no_crypto.js", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := javascript.New()
	content := readFixture(t, "crypto_usage.js")
	findings, err := s.ScanFile("crypto_usage.js", content)
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
	s := javascript.New()
	content := readFixture(t, "crypto_usage.js")
	findings, err := s.ScanFile("crypto_usage.js", content)
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

// ---------------------------------------------------------------------------
// Tier-3 quantum families: @noble Schnorr + BLS (issue #33)
// ---------------------------------------------------------------------------

func TestNobleSchnorrDetection(t *testing.T) {
	s := javascript.New()

	t.Run("@noble/secp256k1 schnorr.sign is quantum-vulnerable", func(t *testing.T) {
		code := []byte(`const { schnorr } = require('@noble/secp256k1');
async function f(msg, priv) { return schnorr.sign(msg, priv); }
`)
		findings, err := s.ScanFile("t.js", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "schnorr" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable &&
				f.RuleID == "cbom-js-schnorr-sign"
		}, "Schnorr sign finding with QuantumVulnerable status")
	})

	t.Run("ESM import schnorr.verify", func(t *testing.T) {
		code := []byte(`import { schnorr } from '@noble/curves/secp256k1';
function f(sig, msg, pub) { return schnorr.verify(sig, msg, pub); }
`)
		findings, err := s.ScanFile("t.ts", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "schnorr" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "Schnorr verify finding")
	})
}

func TestNobleBLSDetection(t *testing.T) {
	s := javascript.New()
	code := []byte(`const bls = require('@noble/bls12-381');
async function f(msg, priv) { return bls.sign(msg, priv); }
`)
	findings, err := s.ScanFile("t.js", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bls" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable &&
			f.RuleID == "cbom-js-bls-sign"
	}, "BLS sign finding with QuantumVulnerable status")
}

// TestNobleQuantumFamiliesZeroFalsePositive ensures schnorr/bls API shapes
// without an anchoring import are never flagged (hard zero-FP constraint).
func TestNobleQuantumFamiliesZeroFalsePositive(t *testing.T) {
	s := javascript.New()
	code := []byte(`// schnorr and bls are signature schemes; this file imports neither.
const bls = { sign: (m, p) => p };
const schnorr = { sign: (m, p) => p };
function go() { return bls.sign('a', 'b') + schnorr.sign('a', 'b'); }
`)
	findings, err := s.ScanFile("noimport.js", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "bls" || f.Properties.AlgorithmFamily == "schnorr" {
			t.Errorf("false positive: %s %s (no anchoring import present)", f.Name, f.RuleID)
		}
	}
}

func TestQuantumFamiliesJSFixture(t *testing.T) {
	s := javascript.New()
	content := readFixture(t, "quantum_families_usage.js")
	findings, err := s.ScanFile("quantum_families_usage.js", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "schnorr" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Schnorr finding in fixture")
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "bls" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "BLS finding in fixture")
}
