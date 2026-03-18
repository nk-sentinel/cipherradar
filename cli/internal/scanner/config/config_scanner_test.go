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
