package configfile

import (
	"os"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestOpenSSLCnfName(t *testing.T) {
	s := NewOpenSSLCnf()
	if s.Name() != "openssl-cnf" {
		t.Errorf("expected name 'openssl-cnf', got %q", s.Name())
	}
}

func TestOpenSSLCnfExtensions(t *testing.T) {
	s := NewOpenSSLCnf()
	exts := s.Extensions()
	if len(exts) != 1 || exts[0] != ".cnf" {
		t.Errorf("expected [.cnf], got %v", exts)
	}
}

func TestOpenSSLCnfScanFile(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/openssl.cnf")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewOpenSSLCnf()
	findings, err := s.ScanFile("openssl.cnf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Should detect weak digest md5.
	assertHasFinding(t, findings, "Weak digest: MD5")

	// Should detect weak digest sha1.
	assertHasFinding(t, findings, "Weak digest: SHA-1")

	// Should detect weak key size 1024.
	assertHasFinding(t, findings, "Weak key size: 1024 bits")
}

func TestOpenSSLCnfWeakKeySizeSeverity(t *testing.T) {
	content := []byte("default_bits = 512\n")
	s := NewOpenSSLCnf()
	findings, err := s.ScanFile("test.cnf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected critical severity for 512-bit key, got %s", findings[0].Severity)
	}
}

func TestOpenSSLCnfStrongConfig(t *testing.T) {
	content := []byte(`
default_md = sha256
default_bits = 4096
`)
	s := NewOpenSSLCnf()
	findings, err := s.ScanFile("good.cnf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for strong config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected: %s", f.Name)
		}
	}
}

func TestOpenSSLCnfEmptyFile(t *testing.T) {
	s := NewOpenSSLCnf()
	findings, err := s.ScanFile("empty.cnf", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}
