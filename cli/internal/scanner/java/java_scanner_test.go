package java_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/java/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/java/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "java")
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

func TestJavaScannerName(t *testing.T) {
	s := java.New()
	if s.Name() != "java" {
		t.Errorf("expected Name() = %q, got %q", "java", s.Name())
	}
}

func TestJavaScannerExtensions(t *testing.T) {
	s := java.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".java": true,
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
// JCA/JCE tests
// ---------------------------------------------------------------------------

func TestJcaCrypto(t *testing.T) {
	s := java.New()
	content := readFixture(t, "JcaCrypto.java")
	findings, err := s.ScanFile("JcaCrypto.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from JcaCrypto.java, got none")
	}

	// DES/ECB (broken, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Properties.Mode == "ecb" &&
			f.Severity == types.SeverityHigh
	}, "DES/ECB finding with HIGH severity")

	// AES-ECB (bad mode, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "ecb" &&
			f.Severity == types.SeverityHigh
	}, "AES/ECB finding with HIGH severity")

	// AES-GCM (good)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm" &&
			f.Severity == types.SeverityInfo
	}, "AES/GCM finding with INFO severity")

	// MD5 (broken hash, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "MD5 hash finding with HIGH severity and Broken quantum status")

	// SHA-1 (broken hash, HIGH severity)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha1" &&
			f.Properties.Primitive == "hash" &&
			f.Severity == types.SeverityHigh
	}, "SHA-1 hash finding with HIGH severity")

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

	// DSA key pair (quantum vulnerable)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "dsa" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "DSA key pair finding with QuantumVulnerable status")

	// Signature (SHA256withRSA)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "signature" &&
			f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "SHA256withRSA signature finding")

	// HMAC
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.Primitive == "mac" &&
			f.Properties.AlgorithmFamily == "hmac" &&
			f.Name == "HmacSHA256"
	}, "HmacSHA256 MAC finding")

	// Constant propagation: AES/CBC resolved from variable
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc" &&
			f.Confidence == types.ConfidenceMedium
	}, "AES/CBC finding via constant propagation with medium confidence")

	// SecretKeySpec for DES
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetRelatedCryptoMaterial &&
			f.Properties.AlgorithmFamily == "des" &&
			f.Properties.MaterialType == "secret-key"
	}, "SecretKeySpec DES key material finding")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// Bouncy Castle tests
// ---------------------------------------------------------------------------

func TestBouncyCastleCrypto(t *testing.T) {
	s := java.New()
	content := readFixture(t, "BouncyCastleCrypto.java")
	findings, err := s.ScanFile("BouncyCastleCrypto.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from BouncyCastleCrypto.java, got none")
	}

	// AES engine
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Name == "AES" &&
			f.Properties.Primitive == "block-cipher"
	}, "Bouncy Castle AES engine finding")

	// DES engine (broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh
	}, "Bouncy Castle DES engine finding with HIGH severity")

	// AES-CBC mode
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "cbc"
	}, "Bouncy Castle AES-CBC finding")

	// AES-GCM mode
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm"
	}, "Bouncy Castle AES-GCM finding")

	// SHA-256 digest
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "Bouncy Castle SHA-256 digest finding")

	// MD5 digest (broken)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh &&
			f.Properties.QuantumStatus == types.Broken
	}, "Bouncy Castle MD5 digest finding with HIGH severity")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// SSL/TLS tests
// ---------------------------------------------------------------------------

func TestSSLConfig(t *testing.T) {
	s := java.New()
	content := readFixture(t, "SSLConfig.java")
	findings, err := s.ScanFile("SSLConfig.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from SSLConfig.java, got none")
	}

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

	// SSL (deprecated, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Name == "SSLv3" &&
			f.Severity == types.SeverityHigh
	}, "SSLv3 finding with HIGH severity")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// ---------------------------------------------------------------------------
// JCA algorithm parser tests
// ---------------------------------------------------------------------------

func TestParseJCAAlgorithm(t *testing.T) {
	tests := []struct {
		input     string
		algorithm string
		mode      string
		padding   string
	}{
		{"AES/CBC/PKCS5Padding", "AES", "CBC", "PKCS5Padding"},
		{"AES/GCM/NoPadding", "AES", "GCM", "NoPadding"},
		{"DES/ECB/PKCS5Padding", "DES", "ECB", "PKCS5Padding"},
		{"AES", "AES", "", ""},
		{"RSA", "RSA", "", ""},
		{"AES/ECB", "AES", "ECB", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := java.ParseJCAAlgorithm(tt.input)
			if result.Algorithm != tt.algorithm {
				t.Errorf("Algorithm: got %q, want %q", result.Algorithm, tt.algorithm)
			}
			if result.Mode != tt.mode {
				t.Errorf("Mode: got %q, want %q", result.Mode, tt.mode)
			}
			if result.Padding != tt.padding {
				t.Errorf("Padding: got %q, want %q", result.Padding, tt.padding)
			}
		})
	}
}

func TestParseSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		wantHash string
		wantAlgo string
	}{
		{"SHA256withRSA", "SHA256", "RSA"},
		{"SHA1withDSA", "SHA1", "DSA"},
		{"SHA384withECDSA", "SHA384", "ECDSA"},
		{"RSA", "", "RSA"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			hash, algo := java.ParseSignatureAlgorithm(tt.input)
			if hash != tt.wantHash {
				t.Errorf("hash: got %q, want %q", hash, tt.wantHash)
			}
			if algo != tt.wantAlgo {
				t.Errorf("algo: got %q, want %q", algo, tt.wantAlgo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Quantum tagging tests
// ---------------------------------------------------------------------------

func TestQuantumTagging(t *testing.T) {
	s := java.New()

	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		code := []byte(`class T { void f() throws Exception { KeyPairGenerator.getInstance("RSA"); } }`)
		findings, err := s.ScanFile("test.java", code)
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
		findings, err := s.ScanFile("test.java", code)
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
		findings, err := s.ScanFile("test.java", code)
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
	s := java.New()
	findings, err := s.ScanFile("empty.java", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCryptoJava(t *testing.T) {
	s := java.New()
	code := []byte(`
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
        int x = 42;
        String s = "test";
    }
}
`)
	findings, err := s.ScanFile("HelloWorld.java", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := java.New()
	content := readFixture(t, "JcaCrypto.java")
	findings, err := s.ScanFile("JcaCrypto.java", content)
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
	s := java.New()
	content := readFixture(t, "JcaCrypto.java")
	findings, err := s.ScanFile("JcaCrypto.java", content)
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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Mode=%s Primitive=%s QS=%s Pass=%d AssetType=%s MaterialType=%s",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass, f.AssetType, f.Properties.MaterialType)
	}
}
