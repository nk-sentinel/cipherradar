package configfile

import (
	"os"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestNginxName(t *testing.T) {
	s := NewNginx()
	if s.Name() != "nginx" {
		t.Errorf("expected name 'nginx', got %q", s.Name())
	}
}

func TestNginxExtensions(t *testing.T) {
	s := NewNginx()
	exts := s.Extensions()
	if len(exts) != 1 || exts[0] != ".conf" {
		t.Errorf("expected [.conf], got %v", exts)
	}
}

func TestNginxScanFile(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/nginx.conf")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewNginx()
	findings, err := s.ScanFile("nginx.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Should detect weak protocols TLSv1 and TLSv1.1.
	assertHasFinding(t, findings, "Weak TLS protocol: TLSv1")
	assertHasFinding(t, findings, "Weak TLS protocol: TLSv1.1")

	// Should detect weak ciphers.
	assertHasFinding(t, findings, "Weak cipher: RC4-SHA")
	assertHasFinding(t, findings, "Weak cipher: DES-CBC3-SHA")

	// Should detect certificate paths.
	assertHasFinding(t, findings, "TLS certificate:")
	assertHasFinding(t, findings, "TLS private key:")

	// The ssl_certificate finding must be emitted as a certificate asset so it
	// survives --only-inventory filtering (hasAssetIdentity includes certificate).
	assertHasFindingType(t, findings, "TLS certificate:", types.AssetCertificate)

	// All findings should have Pass=1.
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("expected Pass=1 for %q, got %d", f.Name, f.Pass)
		}
	}
}

func TestNginxWeakProtocolSeverity(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/nginx.conf")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewNginx()
	findings, err := s.ScanFile("nginx.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "cbom-configfile-nginx-weak-protocol" {
			if f.Severity != types.SeverityHigh && f.Severity != types.SeverityCritical {
				t.Errorf("expected high or critical severity for %q, got %s", f.Name, f.Severity)
			}
		}
	}
}

func TestNginxEmptyFile(t *testing.T) {
	s := NewNginx()
	findings, err := s.ScanFile("empty.conf", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestNginxNonNginxConf(t *testing.T) {
	content := []byte(`
; This is a generic config file
setting = value
other_setting = other_value
`)
	s := NewNginx()
	findings, err := s.ScanFile("generic.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-nginx config, got %d", len(findings))
	}
}

func assertHasFindingType(t *testing.T, findings []types.Finding, nameSubstr string, at types.AssetType) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Name, nameSubstr) && f.AssetType == at {
			return
		}
	}
	t.Errorf("expected finding name containing %q with assetType %q, not found among %d findings", nameSubstr, at, len(findings))
}

func assertHasFinding(t *testing.T, findings []types.Finding, nameSubstr string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Name, nameSubstr) {
			return
		}
	}
	t.Errorf("expected finding with name containing %q, not found among %d findings", nameSubstr, len(findings))
	for _, f := range findings {
		t.Logf("  found: name=%q ruleID=%q", f.Name, f.RuleID)
	}
}
