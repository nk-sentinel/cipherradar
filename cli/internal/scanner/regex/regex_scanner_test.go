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

	// Header-based findings should be LOW confidence. Parsed X.509 certs
	// (rule cbom-regex-pem-certificate-parsed) are HIGH because parsing
	// succeeded — exclude those from this assertion.
	for _, f := range findings {
		if strings.HasSuffix(f.RuleID, "-parsed") || strings.HasSuffix(f.RuleID, "-parse") {
			continue
		}
		if f.Confidence != types.ConfidenceLow {
			t.Errorf("expected LOW confidence for finding %q (rule %s), got %s", f.Name, f.RuleID, f.Confidence)
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

// TestPEMFindingsAreInventory guards against regressing the contract that
// PEM private keys, public keys, and certificates discovered by the regex
// scanner are classified as CategoryInventory so they surface in
// --only-inventory output. The security-warning angle (a private key is
// sensitive!) is captured by Severity, not Category.
func TestPEMFindingsAreInventory(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/regex/test_keys.pem")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := New()
	findings, err := s.ScanFile("test_keys.pem", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	wantPrimitive := map[string]string{
		"cbom-regex-pem-rsa-private":       "PRIVATE-KEY-PEM",
		"cbom-regex-pem-ec-private":        "PRIVATE-KEY-PEM",
		"cbom-regex-pem-pkcs8-private":     "PRIVATE-KEY-PEM",
		"cbom-regex-pem-encrypted-private": "PRIVATE-KEY-PEM",
		"cbom-regex-pem-public":            "PUBLIC-KEY",
		"cbom-regex-pem-certificate":       "CERTIFICATE-X509",
		"cbom-regex-pem-certificate-parse": "CERTIFICATE-X509",
	}

	seenRules := map[string]bool{}
	for _, f := range findings {
		want, ok := wantPrimitive[f.RuleID]
		if !ok {
			continue
		}
		seenRules[f.RuleID] = true
		if f.Category != types.CategoryInventory {
			t.Errorf("rule %s: want CategoryInventory, got %q", f.RuleID, f.Category)
		}
		if f.Properties.AlgorithmPrimitive != want {
			t.Errorf("rule %s: want AlgorithmPrimitive=%q, got %q",
				f.RuleID, want, f.Properties.AlgorithmPrimitive)
		}
	}

	// We expect at least the three PEM types present in the fixture to fire.
	if !seenRules["cbom-regex-pem-rsa-private"] {
		t.Error("expected cbom-regex-pem-rsa-private to fire on fixture")
	}
	if !seenRules["cbom-regex-pem-ec-private"] {
		t.Error("expected cbom-regex-pem-ec-private to fire on fixture")
	}
	if !seenRules["cbom-regex-pem-certificate"] {
		t.Error("expected cbom-regex-pem-certificate to fire on fixture")
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

// TestBase64Key_SuppressesSRIIntegrity guards against the false positive where
// Subresource-Integrity hashes (e.g. package-lock.json "integrity" values) were
// reported as "potential key material". We key off the SRI value shape
// (sha256-/sha384-/sha512- prefix), never the field name.
func TestBase64Key_SuppressesSRIIntegrity(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"sha512", `      "integrity": "sha512-Elp+iwUx5rN5Y8xLt5GRoG20WGoDCQ1Fb1LiGtvwbDavuSk0jhDeZdckHAuzcDzccnkvrEjyWfRx18ggAAAA=="`},
		{"sha384", `  "integrity": "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"`},
		{"sha256", `    "integrity": "sha256-AbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbA="`},
		{"uppercase prefix", `  "x": "SHA512-Elp+iwUx5rN5Y8xLt5GRoG20WGoDCQ1Fb1LiGtvwbDavuSk0jhDeZdckHAuzcDzccnkvrEjyWfRx18ggAAAA=="`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			findings, err := s.ScanFile("package-lock.json", []byte(tc.line+"\n"))
			if err != nil {
				t.Fatalf("ScanFile returned error: %v", err)
			}
			if got := filterByRuleID(findings, "cbom-regex-base64-key"); len(got) != 0 {
				t.Errorf("expected SRI hash to be suppressed, got %d base64-key findings", len(got))
			}
		})
	}
}

// TestBase64Key_DoesNotSuppressGenuineKey ensures the SRI guard only suppresses
// the sha###- shape and does not silence real embedded key material.
func TestBase64Key_DoesNotSuppressGenuineKey(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"raw base64 key", `const KEY = "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq1234567890ABCDEFGH=="`},
		{"sha512sum no hyphen", `  "sha512sum": "AbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb=="`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			findings, err := s.ScanFile("config.txt", []byte(tc.line+"\n"))
			if err != nil {
				t.Fatalf("ScanFile returned error: %v", err)
			}
			if got := filterByRuleID(findings, "cbom-regex-base64-key"); len(got) == 0 {
				t.Errorf("expected genuine base64 key to be detected, got 0 findings")
			}
		})
	}
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
