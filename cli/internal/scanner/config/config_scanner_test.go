package config

import (
	"os"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestName(t *testing.T) {
	s := New()
	if s.Name() != "config" {
		t.Errorf("expected name 'config', got %q", s.Name())
	}
}

func TestExtensions(t *testing.T) {
	s := New()
	exts := s.Extensions()
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}
	expected := map[string]bool{".env": true, ".properties": true}
	for _, ext := range exts {
		if !expected[ext] {
			t.Errorf("unexpected extension %q", ext)
		}
	}
}

func TestEnvScanning(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/config/test.env")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := New()
	findings, err := s.ScanFile("test.env", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// Should find: SECRET_KEY, JWT_SECRET, API_KEY, ENCRYPTION_KEY, AWS_SECRET_ACCESS_KEY
	expectedSecrets := []string{
		"SECRET_KEY",
		"JWT_SECRET",
		"API_KEY",
		"ENCRYPTION_KEY",
		"AWS_SECRET_ACCESS_KEY",
	}

	for _, secret := range expectedSecrets {
		found := false
		for _, f := range findings {
			if strings.Contains(f.Name, secret) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected finding for %q, not found", secret)
		}
	}

	// Should NOT flag NORMAL_VAR and DEBUG
	for _, f := range findings {
		if strings.Contains(f.Name, "NORMAL_VAR") {
			t.Error("should not flag NORMAL_VAR")
		}
		if strings.Contains(f.Name, "DEBUG") {
			t.Error("should not flag DEBUG")
		}
	}

	// All findings should have HIGH severity and MEDIUM confidence
	for _, f := range findings {
		if f.Severity != types.SeverityHigh {
			t.Errorf("expected HIGH severity for %q, got %s", f.Name, f.Severity)
		}
		if f.Confidence != types.ConfidenceMedium {
			t.Errorf("expected MEDIUM confidence for %q, got %s", f.Name, f.Confidence)
		}
		if f.Pass != 1 {
			t.Errorf("expected Pass=1 for %q, got %d", f.Name, f.Pass)
		}
		if f.RuleID != "cbom-config-hardcoded-secret" {
			t.Errorf("expected rule cbom-config-hardcoded-secret for %q, got %s", f.Name, f.RuleID)
		}
	}
}

func TestEnvDoesNotFlagBoringValues(t *testing.T) {
	content := []byte(`
SECRET_KEY=true
API_KEY=false
TOKEN=0
AUTH=null
PASSWORD=none
`)

	s := New()
	findings, err := s.ScanFile("boring.env", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for boring values, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s (snippet: %q)", f.Name, f.Location.Snippet)
		}
	}
}

func TestPropertiesScanning(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/config/test.properties")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := New()
	findings, err := s.ScanFile("test.properties", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// Should find: database.password, encryption.key, ssl.protocol (TLS), jwt.secret
	assertFindingNameContains(t, findings, "database.password")
	assertFindingNameContains(t, findings, "encryption.key")
	assertFindingNameContains(t, findings, "jwt.secret")

	// Should find TLS version reference
	found := false
	for _, f := range findings {
		if f.RuleID == "cbom-config-tls-version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TLS version finding for ssl.protocol=TLSv1")
	}

	// Should find algorithm reference for encryption.algorithm=AES
	algoFound := false
	for _, f := range findings {
		if f.RuleID == "cbom-config-algorithm-ref" {
			algoFound = true
			break
		}
	}
	if !algoFound {
		t.Error("expected algorithm reference finding for encryption.algorithm=AES")
	}

	// Should NOT flag normal.setting
	for _, f := range findings {
		if strings.Contains(f.Name, "normal.setting") {
			t.Error("should not flag normal.setting")
		}
	}
}

func TestPropertiesDoesNotFlagNormalSettings(t *testing.T) {
	content := []byte(`
app.name=MyApplication
server.port=8080
logging.level=INFO
`)

	s := New()
	findings, err := s.ScanFile("normal.properties", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for normal properties, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s (rule: %s)", f.Name, f.RuleID)
		}
	}
}

func TestEmptyFile(t *testing.T) {
	s := New()

	findings, err := s.ScanFile("empty.env", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error for empty .env: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty .env, got %d", len(findings))
	}

	findings, err = s.ScanFile("empty.properties", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error for empty .properties: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty .properties, got %d", len(findings))
	}
}

func TestFileWithNoSecrets(t *testing.T) {
	content := []byte(`# This is a comment
DATABASE_HOST=localhost
DATABASE_PORT=5432
LOG_LEVEL=debug
APP_NAME=myapp
`)

	s := New()
	findings, err := s.ScanFile("clean.env", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean .env, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s (snippet: %q)", f.Name, f.Location.Snippet)
		}
	}
}

func TestPropertiesComments(t *testing.T) {
	content := []byte(`# database.password=secret
! another.password=hidden
valid.key=visible
`)

	s := New()
	findings, err := s.ScanFile("comments.properties", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// Only valid.key should potentially match, but it's "key" with non-secret value
	// The comments should be skipped entirely
	for _, f := range findings {
		if strings.Contains(f.Location.Snippet, "#") || strings.Contains(f.Location.Snippet, "!") {
			t.Errorf("should not flag commented lines, but found: %s", f.Location.Snippet)
		}
	}
}

// TestHardcodedSecretIsInventory guards the contract that hardcoded-secret
// findings (from .env and .properties files) are CategoryInventory so they
// surface in `--only-inventory` runs alongside other discovered crypto
// assets. The HIGH severity captures the security-warning angle; the
// category captures "this is an asset we discovered".
func TestHardcodedSecretIsInventory(t *testing.T) {
	content := []byte(`SECRET_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
API_KEY=sk-proj-abc123def456
`)

	s := New()
	findings, err := s.ScanFile("inv.env", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.RuleID != "cbom-config-hardcoded-secret" {
			t.Errorf("%s: wrong rule %q", f.Name, f.RuleID)
		}
		if f.Category != types.CategoryInventory {
			t.Errorf("%s: want CategoryInventory, got %q", f.Name, f.Category)
		}
		if f.Maturity != types.MaturityStable {
			t.Errorf("%s: want MaturityStable, got %q", f.Name, f.Maturity)
		}
		if !f.DefaultEnabled {
			t.Errorf("%s: want DefaultEnabled=true", f.Name)
		}
		if f.Properties.AlgorithmPrimitive != "HARDCODED-SECRET" {
			t.Errorf("%s: want AlgorithmPrimitive=HARDCODED-SECRET, got %q",
				f.Name, f.Properties.AlgorithmPrimitive)
		}
	}
}

// TestHardcodedSecretInventoryProperties applies to .properties files as well.
func TestHardcodedSecretInventoryPropertiesFile(t *testing.T) {
	content := []byte(`database.password=SuperSecret123!
auth.jwt.secret=eyJhbGciOiJSUzI1NiJ9
crypto.symmetric.key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`)

	s := New()
	findings, err := s.ScanFile("inv.properties", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	secretFindings := 0
	for _, f := range findings {
		if f.RuleID != "cbom-config-hardcoded-secret" {
			continue
		}
		secretFindings++
		if f.Category != types.CategoryInventory {
			t.Errorf("%s: want CategoryInventory, got %q", f.Name, f.Category)
		}
		if f.Properties.AlgorithmPrimitive != "HARDCODED-SECRET" {
			t.Errorf("%s: want AlgorithmPrimitive=HARDCODED-SECRET, got %q",
				f.Name, f.Properties.AlgorithmPrimitive)
		}
	}
	if secretFindings != 3 {
		t.Fatalf("expected 3 hardcoded-secret findings, got %d", secretFindings)
	}
}

// TestSkipsTemplatePlaceholders ensures we don't fire on obvious unfilled
// placeholders that templates leave behind. Without this, .env.example
// files and CI templates would generate noise in --only-inventory.
func TestSkipsTemplatePlaceholders(t *testing.T) {
	content := []byte(`API_KEY=${MY_API_KEY}
SECRET_KEY=<your_secret_here>
JWT_SECRET=changeme
DB_PASSWORD={{password}}
TOKEN=%TOKEN_VAR%
AUTH_TOKEN=your_token_here
ANOTHER=xxx
EMPTY_QUOTED=""
SHORT=ab
PLACEHOLDER=[REDACTED]
PASSWORD_FIELD=placeholder
`)

	s := New()
	findings, err := s.ScanFile("template.env", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings on template placeholders, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s (snippet: %q)", f.Name, f.Location.Snippet)
		}
	}
}

// TestRealSecretsSurviveFiltering verifies that high-entropy real-looking
// secrets are NOT mistakenly suppressed by the placeholder heuristics.
func TestRealSecretsSurviveFiltering(t *testing.T) {
	content := []byte(`API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
DATABASE_PASSWORD=SuperSecret123!
`)

	s := New()
	findings, err := s.ScanFile("real.env", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 4 {
		t.Errorf("expected 4 findings (all real secrets), got %d", len(findings))
		for _, f := range findings {
			t.Logf("  found: %s", f.Name)
		}
	}
}

// --- helpers ---

func assertFindingNameContains(t *testing.T, findings []types.Finding, substr string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Name, substr) {
			return
		}
	}
	t.Errorf("expected finding with name containing %q, not found among %d findings", substr, len(findings))
	for _, f := range findings {
		t.Logf("  found: name=%q ruleID=%q", f.Name, f.RuleID)
	}
}
