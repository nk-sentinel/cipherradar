package configfile

import (
	"os"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestHttpdName(t *testing.T) {
	s := NewHttpd()
	if s.Name() != "httpd" {
		t.Errorf("expected name 'httpd', got %q", s.Name())
	}
}

func TestHttpdScanFile(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/httpd.conf")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewHttpd()
	findings, err := s.ScanFile("httpd.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Should detect +SSLv3 (critical).
	assertHasFinding(t, findings, "Insecure protocol: SSLv3")

	// Should detect +TLSv1 (high).
	assertHasFinding(t, findings, "Weak TLS protocol: TLSv1")

	// Should detect weak ciphers.
	assertHasFinding(t, findings, "Weak cipher: RC4-SHA")
	assertHasFinding(t, findings, "Weak cipher: DES-CBC3-SHA")
}

func TestHttpdSSLv3IsCritical(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/httpd.conf")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewHttpd()
	findings, err := s.ScanFile("httpd.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	for _, f := range findings {
		if f.Name == "Insecure protocol: SSLv3" {
			if f.Severity != types.SeverityCritical {
				t.Errorf("expected critical severity for SSLv3, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("SSLv3 finding not found")
}

func TestHttpdEmptyFile(t *testing.T) {
	s := NewHttpd()
	findings, err := s.ScanFile("empty.conf", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestHttpdNonApacheConf(t *testing.T) {
	content := []byte(`
[database]
host = localhost
port = 5432
`)
	s := NewHttpd()
	findings, err := s.ScanFile("generic.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-Apache config, got %d", len(findings))
	}
}
