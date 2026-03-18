package regex

import (
	"os"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestName(t *testing.T) {
	s := New()
	if s.Name() != "regex" {
		t.Errorf("expected name 'regex', got %q", s.Name())
	}
}

func TestExtensions(t *testing.T) {
	s := New()
	if exts := s.Extensions(); len(exts) != 0 {
		t.Errorf("expected nil extensions (universal scanner), got %v", exts)
	}
}

func TestPEMDetection(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/regex/test_keys.pem")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := New()
	findings, err := s.ScanFile("test_keys.pem", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// Should find: RSA Private Key, Certificate, EC Private Key
	pemFindings := filterByRulePrefix(findings, "cbom-regex-pem-")
	if len(pemFindings) < 3 {
		t.Errorf("expected at least 3 PEM findings, got %d", len(pemFindings))
		for _, f := range pemFindings {
			t.Logf("  PEM finding: %s (%s)", f.Name, f.RuleID)
		}
	}

	// Check specific PEM types are found
	assertFindingExists(t, pemFindings, "RSA Private Key", "cbom-regex-pem-rsa-private")
	assertFindingExists(t, pemFindings, "EC Private Key", "cbom-regex-pem-ec-private")
	assertFindingExists(t, pemFindings, "Certificate", "cbom-regex-pem-certificate")

	// Verify severity for private keys is HIGH
	for _, f := range pemFindings {
		if strings.Contains(f.Name, "Private Key") {
			if f.Severity != types.SeverityHigh {
				t.Errorf("expected HIGH severity for %q, got %s", f.Name, f.Severity)
			}
		}
	}

	// Verify confidence is always LOW for regex scanner
	for _, f := range findings {
		if f.Confidence != types.ConfidenceLow {
			t.Errorf("expected LOW confidence for finding %q, got %s", f.Name, f.Confidence)
		}
	}

	// Verify Pass is always 1
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("expected Pass=1 for finding %q, got %d", f.Name, f.Pass)
		}
	}
}

func TestAlgorithmStringDetection(t *testing.T) {
	content := []byte(`
config.hash = "MD5"
algo = "SHA-1"
cipher = "DES"
modern = "AES-256"
safe_hash = "SHA-256"
`)

	s := New()
	findings, err := s.ScanFile("test_algos.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	algoFindings := filterByRulePrefix(findings, "cbom-regex-algo-")

	assertFindingExists(t, algoFindings, "MD5", "cbom-regex-algo-md5")
	assertFindingExists(t, algoFindings, "SHA-1", "cbom-regex-algo-sha-1")
	assertFindingExists(t, algoFindings, "DES", "cbom-regex-algo-des")
	assertFindingExists(t, algoFindings, "AES-256", "cbom-regex-algo-aes-256")
	assertFindingExists(t, algoFindings, "SHA-256", "cbom-regex-algo-sha-256")

	// Broken algorithms should be MEDIUM severity
	for _, f := range algoFindings {
		if f.Name == "MD5" || f.Name == "DES" || f.Name == "SHA-1" {
			if f.Severity != types.SeverityMedium {
				t.Errorf("expected MEDIUM severity for broken algo %q, got %s", f.Name, f.Severity)
			}
		}
	}

	// Safe algorithms should be INFO severity
	for _, f := range algoFindings {
		if f.Name == "AES-256" || f.Name == "SHA-256" {
			if f.Severity != types.SeverityInfo {
				t.Errorf("expected INFO severity for safe algo %q, got %s", f.Name, f.Severity)
			}
		}
	}
}

func TestNoFalsePositivesOnNormalText(t *testing.T) {
	content := []byte(`This is a normal text file.
It contains no cryptographic patterns.
Just regular prose and sentences.
The weather is nice today.
`)

	s := New()
	findings, err := s.ScanFile("normal.txt", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings on normal text, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s (rule: %s, snippet: %q)", f.Name, f.RuleID, f.Location.Snippet)
		}
	}
}

func TestEmptyFile(t *testing.T) {
	s := New()
	findings, err := s.ScanFile("empty.txt", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestBinaryContentDoesNotCrash(t *testing.T) {
	// Create binary content with NUL bytes
	content := make([]byte, 1024)
	content[0] = 0x00
	content[1] = 0xFF
	content[2] = 0x89 // PNG header byte
	content[3] = 0x50

	s := New()
	findings, err := s.ScanFile("binary.dat", content)
	if err != nil {
		t.Fatalf("ScanFile returned error on binary content: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for binary file, got %d", len(findings))
	}
}

func TestProtocolDetection(t *testing.T) {
	content := []byte(`
ssl_context.protocol = SSLv3
tls_version = TLSv1.0
newer = TLSv1.1
`)

	s := New()
	findings, err := s.ScanFile("protocols.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	algoFindings := filterByRulePrefix(findings, "cbom-regex-algo-")
	assertFindingExists(t, algoFindings, "SSLv3", "cbom-regex-algo-sslv3")
	assertFindingExists(t, algoFindings, "TLSv1.0", "cbom-regex-algo-tlsv10")
	assertFindingExists(t, algoFindings, "TLSv1.1", "cbom-regex-algo-tlsv11")

	// All should be protocol asset type
	for _, f := range algoFindings {
		if f.Name == "SSLv3" || f.Name == "TLSv1.0" || f.Name == "TLSv1.1" {
			if f.AssetType != types.AssetProtocol {
				t.Errorf("expected protocol asset type for %q, got %s", f.Name, f.AssetType)
			}
		}
	}
}

func TestHexKeyDetection(t *testing.T) {
	content := []byte(`encryption_key = 0123456789abcdef0123456789abcdef
normal_text = hello world
`)

	s := New()
	findings, err := s.ScanFile("hex_test.txt", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	hexFindings := filterByRuleID(findings, "cbom-regex-hex-key")
	if len(hexFindings) == 0 {
		t.Error("expected at least 1 hex key finding")
	}

	for _, f := range hexFindings {
		if f.Severity != types.SeverityInfo {
			t.Errorf("expected INFO severity for hex key finding, got %s", f.Severity)
		}
		if f.AssetType != types.AssetRelatedCryptoMaterial {
			t.Errorf("expected related-crypto-material asset type, got %s", f.AssetType)
		}
	}
}

func TestLocationAccuracy(t *testing.T) {
	content := []byte("line one\n-----BEGIN RSA PRIVATE KEY-----\nline three\n")

	s := New()
	findings, err := s.ScanFile("location_test.pem", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	pemFindings := filterByRuleID(findings, "cbom-regex-pem-rsa-private")
	if len(pemFindings) == 0 {
		t.Fatal("expected RSA private key finding")
	}

	f := pemFindings[0]
	if f.Location.StartLine != 2 {
		t.Errorf("expected StartLine=2, got %d", f.Location.StartLine)
	}
	if f.Location.File != "location_test.pem" {
		t.Errorf("expected file 'location_test.pem', got %q", f.Location.File)
	}
}

// --- helpers ---

func filterByRulePrefix(findings []types.Finding, prefix string) []types.Finding {
	var filtered []types.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, prefix) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func filterByRuleID(findings []types.Finding, ruleID string) []types.Finding {
	var filtered []types.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func assertFindingExists(t *testing.T, findings []types.Finding, name, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.Name == name && f.RuleID == ruleID {
			return
		}
	}
	t.Errorf("expected finding with name=%q ruleID=%q, not found among %d findings", name, ruleID, len(findings))
	for _, f := range findings {
		t.Logf("  found: name=%q ruleID=%q", f.Name, f.RuleID)
	}
}
