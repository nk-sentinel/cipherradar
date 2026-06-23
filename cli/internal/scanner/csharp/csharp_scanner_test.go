package csharp_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/csharp"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/csharp/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/csharp/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "csharp")
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

func TestCSharpScannerName(t *testing.T) {
	s := csharp.New()
	if s.Name() != "csharp" {
		t.Errorf("expected Name() = %q, got %q", "csharp", s.Name())
	}
}

func TestCSharpScannerExtensions(t *testing.T) {
	s := csharp.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".cs": true,
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
// CryptoUsage.cs tests
// ---------------------------------------------------------------------------

func TestCryptoUsage(t *testing.T) {
	s := csharp.New()
	content := readFixture(t, "CryptoUsage.cs")
	findings, err := s.ScanFile("CryptoUsage.cs", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from CryptoUsage.cs, got none")
	}

	// AES (good, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher" &&
			f.Severity == types.SeverityInfo
	}, "AES finding with INFO severity")

	// DES (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh
	}, "DES finding with HIGH severity")

	// TripleDES (HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "3des" &&
			f.Severity == types.SeverityHigh
	}, "TripleDES finding with HIGH severity")

	// RSA key generation with key size
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.Primitive == "pke" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA finding with QuantumVulnerable status")

	// ECDSA
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ecdsa" &&
			f.Properties.Primitive == "signature"
	}, "ECDSA finding")

	// SHA-256 (good hash, INFO severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 hash finding with INFO severity and QuantumSafe status")

	// SHA-1 (broken hash, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha1" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh
	}, "SHA-1 hash finding with HIGH severity")

	// MD5 (broken hash, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "MD5 hash finding with HIGH severity and Broken quantum status")

	// HMACSHA256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "mac" &&
			f.Properties.AlgorithmFamily == "hmac" &&
			f.Name == "HMACSHA256"
	}, "HMACSHA256 MAC finding")

	// PBKDF2
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "kdf" &&
			f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.Name == "PBKDF2"
	}, "PBKDF2 key derivation finding")

	// TLS 1.0 (deprecated, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLSv1.0" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.ProtocolVersion == "1.0"
	}, "TLSv1.0 finding with HIGH severity")

	// TLS 1.1 (deprecated, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLSv1.1" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.ProtocolVersion == "1.1"
	}, "TLSv1.1 finding with HIGH severity")

	// TLS 1.2 (good, INFO)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLSv1.2" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.ProtocolVersion == "1.2"
	}, "TLSv1.2 finding with INFO severity")

	// TLS 1.3 (good, INFO)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "TLSv1.3" &&
			f.Severity == types.SeverityInfo &&
			f.Properties.ProtocolVersion == "1.3"
	}, "TLSv1.3 finding with INFO severity")

	// BouncyCastle AES engine
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.RuleID == "cbom-csharp-bc-engine-aes"
	}, "BouncyCastle AES engine finding")

	// BouncyCastle DES engine (HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.RuleID == "cbom-csharp-bc-engine-des" &&
			f.Severity == types.SeverityHigh
	}, "BouncyCastle DES engine finding with HIGH severity")

	// BouncyCastle RSA engine
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.RuleID == "cbom-csharp-bc-engine-rsa"
	}, "BouncyCastle RSA engine finding")

	// BouncyCastle SHA-256 digest
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.RuleID == "cbom-csharp-bc-digest-sha-256"
	}, "BouncyCastle SHA-256 digest finding")

	// BouncyCastle MD5 digest (HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.RuleID == "cbom-csharp-bc-digest-md5" &&
			f.Severity == types.SeverityHigh
	}, "BouncyCastle MD5 digest finding with HIGH severity")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}

	// All rule IDs must start with cbom-csharp-
	for _, f := range findings {
		if f.RuleID != "" && !hasPrefix(f.RuleID, "cbom-csharp-") {
			t.Errorf("finding %s has RuleID=%q, expected prefix cbom-csharp-", f.ID, f.RuleID)
		}
	}
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	s := csharp.New()

	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`class T { void f() { RSA.Create(2048); } }`)
		findings, err := s.ScanFile("test.cs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "rsa" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "RSA finding with QuantumVulnerable status")
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		code := []byte(`class T { void f() { Aes.Create(); } }`)
		findings, err := s.ScanFile("test.cs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "aes" &&
				f.Properties.QuantumStatus == types.QuantumSafe
		}, "AES finding with QuantumSafe status")
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		code := []byte(`class T { void f() { MD5.Create(); } }`)
		findings, err := s.ScanFile("test.cs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "md5" &&
				f.Properties.QuantumStatus == types.Broken
		}, "MD5 finding with Broken status")
	})

	t.Run("ECDSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`class T { void f() { ECDsa.Create(); } }`)
		findings, err := s.ScanFile("test.cs", code)
		if err != nil {
			t.Fatalf("ScanFile failed: %v", err)
		}
		assertFindingExists(t, findings, func(f types.Finding) bool {
			return f.Properties.AlgorithmFamily == "ecdsa" &&
				f.Properties.QuantumStatus == types.QuantumVulnerable
		}, "ECDSA finding with QuantumVulnerable status")
	})
}

// ---------------------------------------------------------------------------
// Severity tests
// ---------------------------------------------------------------------------

func TestSeverityLevels(t *testing.T) {
	s := csharp.New()

	tests := []struct {
		name     string
		code     string
		severity types.Severity
		family   string
	}{
		{"MD5 is HIGH", `class T { void f() { MD5.Create(); } }`, types.SeverityHigh, "md5"},
		{"SHA1 is HIGH", `class T { void f() { SHA1.Create(); } }`, types.SeverityHigh, "sha1"},
		{"DES is HIGH", `class T { void f() { DES.Create(); } }`, types.SeverityHigh, "des"},
		{"TripleDES is HIGH", `class T { void f() { TripleDES.Create(); } }`, types.SeverityHigh, "3des"},
		{"AES is INFO", `class T { void f() { Aes.Create(); } }`, types.SeverityInfo, "aes"},
		{"SHA256 is INFO", `class T { void f() { SHA256.Create(); } }`, types.SeverityInfo, "sha-256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := s.ScanFile("test.cs", []byte(tt.code))
			if err != nil {
				t.Fatalf("ScanFile failed: %v", err)
			}
			assertFindingExists(t, findings, func(f types.Finding) bool {
				return f.Properties.AlgorithmFamily == tt.family &&
					f.Severity == tt.severity
			}, tt.name)
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := csharp.New()
	findings, err := s.ScanFile("empty.cs", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCryptoCSharp(t *testing.T) {
	s := csharp.New()
	code := []byte(`
using System;

namespace HelloWorld
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
            var x = 42;
            var s = "test";
        }
    }
}
`)
	findings, err := s.ScanFile("HelloWorld.cs", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := csharp.New()
	content := readFixture(t, "CryptoUsage.cs")
	findings, err := s.ScanFile("CryptoUsage.cs", content)
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
	s := csharp.New()
	content := readFixture(t, "CryptoUsage.cs")
	findings, err := s.ScanFile("CryptoUsage.cs", content)
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
// TLS-specific tests
// ---------------------------------------------------------------------------

func TestTLSSeverity(t *testing.T) {
	s := csharp.New()

	tests := []struct {
		name     string
		code     string
		tlsName  string
		severity types.Severity
		version  string
	}{
		{"TLS 1.0 is HIGH", `SslProtocols.Tls`, "TLSv1.0", types.SeverityHigh, "1.0"},
		{"TLS 1.1 is HIGH", `SslProtocols.Tls11`, "TLSv1.1", types.SeverityHigh, "1.1"},
		{"TLS 1.2 is INFO", `SslProtocols.Tls12`, "TLSv1.2", types.SeverityInfo, "1.2"},
		{"TLS 1.3 is INFO", `SslProtocols.Tls13`, "TLSv1.3", types.SeverityInfo, "1.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := s.ScanFile("test.cs", []byte(tt.code))
			if err != nil {
				t.Fatalf("ScanFile failed: %v", err)
			}
			assertFindingExists(t, findings, func(f types.Finding) bool {
				return f.Name == tt.tlsName &&
					f.Severity == tt.severity &&
					f.Properties.ProtocolVersion == tt.version
			}, tt.name)
		})
	}
}

// ---------------------------------------------------------------------------
// BouncyCastle-specific tests
// ---------------------------------------------------------------------------

func TestBouncyCastleEngines(t *testing.T) {
	s := csharp.New()

	tests := []struct {
		name     string
		code     string
		family   string
		severity types.Severity
	}{
		{"AesEngine", `class T { void f() { new AesEngine(); } }`, "aes", types.SeverityInfo},
		{"DesEngine HIGH", `class T { void f() { new DesEngine(); } }`, "des", types.SeverityHigh},
		{"RsaEngine", `class T { void f() { new RsaEngine(); } }`, "rsa", types.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := s.ScanFile("test.cs", []byte(tt.code))
			if err != nil {
				t.Fatalf("ScanFile failed: %v", err)
			}
			assertFindingExists(t, findings, func(f types.Finding) bool {
				return f.Properties.AlgorithmFamily == tt.family &&
					f.Severity == tt.severity &&
					hasPrefix(f.RuleID, "cbom-csharp-bc-engine-")
			}, tt.name)
		})
	}
}

// ---------------------------------------------------------------------------
// HMAC tests
// ---------------------------------------------------------------------------

func TestHMACDetection(t *testing.T) {
	s := csharp.New()

	code := []byte(`
class T {
    void f() {
        var hmac256 = new HMACSHA256(key);
        var hmac384 = new HMACSHA384(key);
        var hmac512 = new HMACSHA512(key);
    }
}
`)
	findings, err := s.ScanFile("test.cs", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HMACSHA256" && f.Properties.Primitive == "mac"
	}, "HMACSHA256 finding")

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HMACSHA384" && f.Properties.Primitive == "mac"
	}, "HMACSHA384 finding")

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "HMACSHA512" && f.Properties.Primitive == "mac"
	}, "HMACSHA512 finding")
}

// ---------------------------------------------------------------------------
// PBKDF2 tests
// ---------------------------------------------------------------------------

func TestPBKDF2Detection(t *testing.T) {
	s := csharp.New()

	code := []byte(`var kdf = new Rfc2898DeriveBytes("password", salt, 100000);`)
	findings, err := s.ScanFile("test.cs", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "PBKDF2" &&
			f.Properties.Primitive == "kdf" &&
			f.Properties.AlgorithmFamily == "pbkdf2"
	}, "PBKDF2 finding")
}

// ---------------------------------------------------------------------------
// RSA key size test
// ---------------------------------------------------------------------------

func TestRSAKeySize(t *testing.T) {
	s := csharp.New()

	code := []byte(`class T { void f() { RSA.Create(4096); } }`)
	findings, err := s.ScanFile("test.cs", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.KeySize == 4096 &&
			f.Name == "RSA-4096"
	}, "RSA-4096 finding with key size")
}

// ---------------------------------------------------------------------------
// DSA / ECDH factory detection — issue #34 Tier-1 gap fill
// ---------------------------------------------------------------------------

func TestAsymmetricUsage(t *testing.T) {
	s := csharp.New()
	content := readFixture(t, "AsymmetricUsage.cs")
	findings, err := s.ScanFile("AsymmetricUsage.cs", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from AsymmetricUsage.cs, got none")
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "dsa" &&
			f.Properties.Primitive == "signature" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "DSA finding flagged quantum-vulnerable")

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ecdh" &&
			f.Properties.Primitive == "key-agree" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "ECDH finding flagged quantum-vulnerable")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestCSharpKeySizePropertyAssignment(t *testing.T) {
	scan := func(src string) []types.Finding {
		f, err := csharp.New().ScanFile("Test.cs", []byte(src))
		if err != nil {
			t.Fatalf("ScanFile error: %v", err)
		}
		return f
	}

	t.Run("KeySize property assignment", func(t *testing.T) {
		f := scan(`class T { void M() {
			var rsa = RSA.Create();
			rsa.KeySize = 2048;
		}}`)
		assertFindingExists(t, f, func(x types.Finding) bool {
			return x.Properties.AlgorithmFamily == "rsa" && x.Properties.KeySize == 2048
		}, "RSA with KeySize=2048 from property assignment")
	})

	t.Run("KeySize via const", func(t *testing.T) {
		f := scan(`class T { void M() {
			int bits = 3072;
			var rsa = RSA.Create();
			rsa.KeySize = bits;
		}}`)
		assertFindingExists(t, f, func(x types.Finding) bool {
			return x.Properties.AlgorithmFamily == "rsa" && x.Properties.KeySize == 3072
		}, "RSA with KeySize=3072 resolved from const")
	})

	t.Run("Create(2048) ctor-arg still works", func(t *testing.T) {
		f := scan(`class T { void M() {
			var rsa = RSA.Create(2048);
		}}`)
		assertFindingExists(t, f, func(x types.Finding) bool {
			return x.Properties.AlgorithmFamily == "rsa" && x.Properties.KeySize == 2048
		}, "RSA.Create(2048) ctor-arg regression")
	})

	t.Run("Aes KeySize property assignment", func(t *testing.T) {
		f := scan(`class T { void M() {
			var aes = Aes.Create();
			aes.KeySize = 256;
		}}`)
		assertFindingExists(t, f, func(x types.Finding) bool {
			return x.Properties.AlgorithmFamily == "aes" && x.Properties.KeySize == 256
		}, "AES with KeySize=256 from property assignment")
	})
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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Mode=%s Primitive=%s QS=%s Pass=%d AssetType=%s MaterialType=%s ProtocolVersion=%s KeySize=%d",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass, f.AssetType, f.Properties.MaterialType,
			f.Properties.ProtocolVersion, f.Properties.KeySize)
	}
}
