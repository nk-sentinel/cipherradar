package dart_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/dart"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDir returns the absolute path to the testdata/dart/ directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/dart/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	dir := filepath.Join(cliDir, "testdata", "dart")
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

func TestDartScannerName(t *testing.T) {
	s := dart.New()
	if s.Name() != "dart" {
		t.Errorf("expected Name() = %q, got %q", "dart", s.Name())
	}
}

func TestDartScannerExtensions(t *testing.T) {
	s := dart.New()
	exts := s.Extensions()
	expected := map[string]bool{".dart": true}
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
	s := dart.New()
	content := readFixture(t, "crypto_usage.dart")
	findings, err := s.ScanFile("crypto_usage.dart", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from crypto_usage.dart, got none")
	}

	// SHA-256 via package:crypto
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-crypto-sha256" &&
			f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "SHA-256 finding with QuantumSafe status")

	// SHA-1 (broken, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-crypto-sha1" &&
			f.Properties.AlgorithmFamily == "sha1" &&
			f.Severity == types.SeverityHigh
	}, "SHA-1 finding with HIGH severity")

	// MD5 (broken, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-crypto-md5" &&
			f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh
	}, "MD5 finding with HIGH severity")

	// HMAC-SHA256
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-crypto-hmac-sha256" &&
			f.Properties.Primitive == "mac"
	}, "HMAC-SHA256 finding")

	// AES via pointycastle
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-aes" &&
			f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.QuantumStatus == types.QuantumSafe
	}, "AES pointycastle finding with QuantumSafe status")

	// DES via pointycastle (broken, HIGH)
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-des" &&
			f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh
	}, "DES pointycastle finding with HIGH severity")

	// RSA via pointycastle
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-rsa" &&
			f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA pointycastle finding with QuantumVulnerable status")

	// SHA256Digest via pointycastle
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-sha256" &&
			f.Properties.Primitive == "hash"
	}, "SHA256Digest pointycastle finding")

	// PBKDF2 via pointycastle
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-pbkdf2" &&
			f.Properties.Primitive == "kdf"
	}, "PBKDF2 pointycastle finding")

	// FortunaRandom
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-fortuna" &&
			f.Properties.Primitive == "random"
	}, "FortunaRandom finding")

	// Encrypter from package:encrypt
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-encrypt-encrypter" &&
			f.Properties.AlgorithmFamily == "aes"
	}, "Encrypter finding")

	// AES-GCM via package:encrypt — mode must be captured as AEAD.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-encrypt-encrypter" &&
			f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Mode == "gcm" &&
			f.Properties.Primitive == "ae" &&
			f.Name == "AES-GCM"
	}, "AES-GCM finding with mode=gcm and ae primitive")

	// AES-CBC standalone — mode captured, block-cipher primitive.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-encrypt-aes" &&
			f.Properties.Mode == "cbc" &&
			f.Properties.Primitive == "block-cipher" &&
			f.Name == "AES-CBC"
	}, "AES-CBC standalone finding with mode=cbc")

	// ECDSA / EC keygen via pointycastle (quantum-vulnerable).
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-eckeygen" &&
			f.Properties.AlgorithmFamily == "ecdsa" &&
			f.Properties.Primitive == "signature" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "ECDSA keygen finding with QuantumVulnerable status")

	// scrypt KDF via pointycastle.
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-pointycastle-scrypt" &&
			f.Properties.AlgorithmFamily == "scrypt" &&
			f.Properties.Primitive == "kdf"
	}, "scrypt KDF finding")

	// TLS via dart:io SecureSocket (protocol asset).
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-dart-io-tls" &&
			f.AssetType == types.AssetProtocol &&
			f.Properties.ProtocolType == "tls" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "TLS protocol finding via SecureSocket")

	// All findings must have Pass = 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("finding %s has Pass=%d, expected 1", f.ID, f.Pass)
		}
	}
}

// TestNoFalsePositivesOnSubstrings verifies that identifiers merely containing
// "AES" or "Socket" substrings (WebSocket, prose) do not trigger findings.
func TestNoFalsePositivesOnSubstrings(t *testing.T) {
	s := dart.New()
	code := []byte(`
final webSocketUrl = 'wss://example.com/feed';
final phrase = 'PHRASES contain AES letters but are not crypto';
final notAes = computeAesthetics();
`)
	findings, err := s.ScanFile("substrings.dart", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("spurious finding: %s (%s) at line %d", f.Name, f.RuleID, f.Location.StartLine)
		}
	}
}

// TestEncrypterWrappedAESSingleFinding verifies the Encrypter(AES(...)) idiom
// yields exactly one AES finding (no duplicate from the standalone AES detector).
func TestEncrypterWrappedAESSingleFinding(t *testing.T) {
	s := dart.New()
	code := []byte(`final e = Encrypter(AES(key, mode: AESMode.gcm));`)
	findings, err := s.ScanFile("wrapped.dart", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	count := 0
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "aes" {
			count++
			if f.Properties.Mode != "gcm" {
				t.Errorf("expected mode=gcm, got %q", f.Properties.Mode)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 AES finding for wrapped idiom, got %d", count)
	}
}

// TestECKeyGeneratorNoParamsDoubleMatch verifies the EC keygen detector matches
// the generator constructor but not the ECKeyGeneratorParameters argument.
func TestECKeyGeneratorNoParamsDoubleMatch(t *testing.T) {
	s := dart.New()
	code := []byte(`final g = ECKeyGenerator()..init(ECKeyGeneratorParameters(curve));`)
	findings, err := s.ScanFile("eckeygen.dart", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	count := 0
	for _, f := range findings {
		if f.RuleID == "cbom-dart-pointycastle-eckeygen" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 ECKeyGenerator finding, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Constant propagation tests
// ---------------------------------------------------------------------------

func TestConstPropagation(t *testing.T) {
	t.Run("direct constprop API", func(t *testing.T) {
		cp := dart.NewConstPropagator()
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
		cp := dart.NewConstPropagator()
		_, ok := cp.Resolve("nonexistent")
		if ok {
			t.Error("expected Resolve for nonexistent variable to return false")
		}
	})

	t.Run("final assignment", func(t *testing.T) {
		cp := dart.NewConstPropagator()
		cp.CollectAssignments([]byte(`final algo = "AES";
var keySize = 256;`))
		val, ok := cp.Resolve("algo")
		if !ok || val != "AES" {
			t.Errorf("expected algo=%q, got %q (ok=%v)", "AES", val, ok)
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
	t.Run("RSA is QuantumVulnerable", func(t *testing.T) {
		qi := dart.GetQuantumInfo("rsa")
		if qi.Status != types.QuantumVulnerable {
			t.Errorf("expected QuantumVulnerable, got %s", qi.Status)
		}
	})

	t.Run("AES is QuantumSafe", func(t *testing.T) {
		qi := dart.GetQuantumInfo("aes")
		if qi.Status != types.QuantumSafe {
			t.Errorf("expected QuantumSafe, got %s", qi.Status)
		}
	})

	t.Run("MD5 is Broken", func(t *testing.T) {
		qi := dart.GetQuantumInfo("md5")
		if qi.Status != types.Broken {
			t.Errorf("expected Broken, got %s", qi.Status)
		}
	})

	t.Run("unknown algo returns QuantumUnknown", func(t *testing.T) {
		qi := dart.GetQuantumInfo("totally-made-up-algo")
		if qi.Status != types.QuantumUnknown {
			t.Errorf("expected QuantumUnknown, got %s", qi.Status)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestEmptyFile(t *testing.T) {
	s := dart.New()
	findings, err := s.ScanFile("empty.dart", []byte(""))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNoCrypto(t *testing.T) {
	s := dart.New()
	code := []byte(`
void main() {
  print('Hello, world!');
  var x = 42;
}
`)
	findings, err := s.ScanFile("no_crypto.dart", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-crypto file, got %d", len(findings))
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	s := dart.New()
	content := readFixture(t, "crypto_usage.dart")
	findings, err := s.ScanFile("crypto_usage.dart", content)
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
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Confidence=%s Family=%s Primitive=%s QS=%s Pass=%d",
			f.ID, f.Name, f.RuleID, f.Severity, f.Confidence,
			f.Properties.AlgorithmFamily, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.Pass)
	}
}
