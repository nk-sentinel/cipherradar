package scanner_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/golang"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/regex"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testdataDetectionDir returns the absolute path to the testdata/detection/ directory.
func testdataDetectionDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go from internal/scanner/ up to cli/
	cliDir := filepath.Join(filepath.Dir(filename), "..", "..")
	dir := filepath.Join(cliDir, "testdata", "detection")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("testdata/detection directory not found: %s", dir)
	}
	return dir
}

func readDetectionFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(testdataDetectionDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return data
}

func findMatch(findings []types.Finding, match func(types.Finding) bool) *types.Finding {
	for i := range findings {
		if match(findings[i]) {
			return &findings[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Python: weak KDF iteration detection
// ---------------------------------------------------------------------------

func TestPythonWeakKDFIterations(t *testing.T) {
	s := python.New()
	content := readDetectionFixture(t, "weak_kdf.py")
	findings, err := s.ScanFile("weak_kdf.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should find PBKDF2 with low iterations (1000) flagged as MEDIUM
	lowIter := findMatch(findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.Severity == types.SeverityMedium
	})
	if lowIter == nil {
		t.Error("expected PBKDF2 finding with MEDIUM severity for low iterations")
		for _, f := range findings {
			t.Logf("  found: Name=%q Severity=%s Family=%s RuleID=%s",
				f.Name, f.Severity, f.Properties.AlgorithmFamily, f.RuleID)
		}
	}
}

// ---------------------------------------------------------------------------
// Java: ECB mode, PKCS1Padding, PBEKeySpec
// ---------------------------------------------------------------------------

func TestJavaECBMode(t *testing.T) {
	s := java.New()
	content := readDetectionFixture(t, "ecb_mode.java")
	findings, err := s.ScanFile("ecb_mode.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// ECB mode should be HIGH severity
	ecb := findMatch(findings, func(f types.Finding) bool {
		return f.Properties.Mode == "ecb" &&
			f.Properties.AlgorithmFamily == "aes" &&
			f.Severity == types.SeverityHigh
	})
	if ecb == nil {
		t.Error("expected AES/ECB finding with HIGH severity")
		logFindings(t, findings)
	}
}

func TestJavaPKCS1Padding(t *testing.T) {
	s := java.New()
	content := readDetectionFixture(t, "ecb_mode.java")
	findings, err := s.ScanFile("ecb_mode.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// RSA/ECB/PKCS1Padding: ECB mode takes priority with HIGH severity,
	// but the padding should still be recorded as pkcs1padding
	pkcs1 := findMatch(findings, func(f types.Finding) bool {
		return f.Properties.Padding == "pkcs1padding" &&
			f.Properties.AlgorithmFamily == "rsa"
	})
	if pkcs1 == nil {
		t.Error("expected RSA finding with PKCS1Padding")
		logFindings(t, findings)
	}

	// Test that a standalone RSA/PKCS1Padding (without ECB) would be MEDIUM
	// by creating inline code
	code := []byte(`import javax.crypto.Cipher;
public class Test {
    public void test() throws Exception {
        Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding");
    }
}`)
	findings2, err := s.ScanFile("test.java", code)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	pkcs1Standalone := findMatch(findings2, func(f types.Finding) bool {
		return f.Properties.Padding == "pkcs1padding" &&
			f.Properties.AlgorithmFamily == "rsa" &&
			f.Severity == types.SeverityMedium
	})
	if pkcs1Standalone == nil {
		t.Error("expected RSA/NONE/PKCS1Padding finding with MEDIUM severity")
		logFindings(t, findings2)
	}
}

func TestJavaPBEKeySpec(t *testing.T) {
	s := java.New()
	content := readDetectionFixture(t, "ecb_mode.java")
	findings, err := s.ScanFile("ecb_mode.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// PBEKeySpec with 1000 iterations should be MEDIUM
	pbe := findMatch(findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "pbkdf2" &&
			f.RuleID == "cbom-java-jca-pbekeyspec-pbkdf2" &&
			f.Severity == types.SeverityMedium
	})
	if pbe == nil {
		t.Error("expected PBEKeySpec/PBKDF2 finding with MEDIUM severity for low iterations")
		logFindings(t, findings)
	}
}

// ---------------------------------------------------------------------------
// Go: PKCS1v15 padding flagging
// ---------------------------------------------------------------------------

func TestGoPKCS1v15(t *testing.T) {
	s := golang.New()
	content := readDetectionFixture(t, "pkcs1v15.go")
	findings, err := s.ScanFile("pkcs1v15.go", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// EncryptPKCS1v15 should be flagged as MEDIUM
	enc := findMatch(findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-go-rsa-encryptpkcs1v15" &&
			f.Severity == types.SeverityMedium &&
			f.Properties.Padding == "pkcs1v15"
	})
	if enc == nil {
		t.Error("expected EncryptPKCS1v15 finding with MEDIUM severity")
		logFindings(t, findings)
	}

	// SignPKCS1v15 should be flagged as MEDIUM
	sig := findMatch(findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-go-rsa-signpkcs1v15" &&
			f.Severity == types.SeverityMedium &&
			f.Properties.Padding == "pkcs1v15"
	})
	if sig == nil {
		t.Error("expected SignPKCS1v15 finding with MEDIUM severity")
		logFindings(t, findings)
	}

	// EncryptOAEP should be INFO (not flagged)
	oaep := findMatch(findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-go-rsa-encryptoaep" &&
			f.Severity == types.SeverityInfo
	})
	if oaep == nil {
		t.Error("expected EncryptOAEP finding with INFO severity")
		logFindings(t, findings)
	}
}

// ---------------------------------------------------------------------------
// Regex: Certificate parsing
// ---------------------------------------------------------------------------

func TestCertificateParsing(t *testing.T) {
	s := regex.New()
	content := readDetectionFixture(t, "expired_cert.pem")
	findings, err := s.ScanFile("expired_cert.pem", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should find the certificate header
	certHeader := findMatch(findings, func(f types.Finding) bool {
		return f.RuleID == "cbom-regex-pem-certificate" &&
			f.AssetType == types.AssetCertificate
	})
	if certHeader == nil {
		t.Error("expected certificate PEM header finding")
		logFindings(t, findings)
	}

	// Should also have a certificate parse attempt. A successfully parsed cert
	// now reports certificateFormat "X.509"; an unparseable block keeps "PEM".
	certParsed := findMatch(findings, func(f types.Finding) bool {
		return (f.RuleID == "cbom-regex-pem-certificate-parsed" || f.RuleID == "cbom-regex-pem-certificate-parse") &&
			f.AssetType == types.AssetCertificate &&
			(f.Properties.CertificateFormat == "X.509" || f.Properties.CertificateFormat == "PEM")
	})
	if certParsed == nil {
		t.Error("expected certificate parsing finding")
		logFindings(t, findings)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func logFindings(t *testing.T, findings []types.Finding) {
	t.Helper()
	t.Logf("findings (%d):", len(findings))
	for _, f := range findings {
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Family=%s Mode=%s Padding=%s Pass=%d",
			f.ID, f.Name, f.RuleID, f.Severity,
			f.Properties.AlgorithmFamily, f.Properties.Mode, f.Properties.Padding, f.Pass)
	}
}
