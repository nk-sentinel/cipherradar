package configfile

import (
	"os"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestDockerfileName(t *testing.T) {
	s := NewDockerfile()
	if s.Name() != "dockerfile" {
		t.Errorf("expected name 'dockerfile', got %q", s.Name())
	}
}

func TestDockerfileExtensions(t *testing.T) {
	s := NewDockerfile()
	exts := s.Extensions()
	if exts != nil {
		t.Errorf("expected nil extensions for dockerfile scanner, got %v", exts)
	}
}

func TestDockerfileScanFile(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/Dockerfile")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewDockerfile()
	findings, err := s.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Should detect unpinned openssl install.
	assertHasFinding(t, findings, "Unpinned OpenSSL install")

	// Should detect EXPOSE 443.
	assertHasFinding(t, findings, "TLS endpoint: EXPOSE 443")

	// All findings should have Pass=1.
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("expected Pass=1 for %q, got %d", f.Name, f.Pass)
		}
	}
}

func TestDockerfileUnpinnedOpenSSLCount(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/Dockerfile")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewDockerfile()
	findings, err := s.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	count := 0
	for _, f := range findings {
		if f.RuleID == "cbom-configfile-dockerfile-unpinned-openssl" {
			count++
		}
	}
	// The test fixture has 2 unpinned openssl installs.
	if count != 2 {
		t.Errorf("expected 2 unpinned openssl findings, got %d", count)
	}
}

func TestDockerfilePinnedOpenSSL(t *testing.T) {
	content := []byte(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssl=3.0.2-0ubuntu1
EXPOSE 443
`)
	s := NewDockerfile()
	findings, err := s.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "cbom-configfile-dockerfile-unpinned-openssl" {
			t.Error("should not flag pinned openssl install")
		}
	}
}

func TestDockerfileTLSPort(t *testing.T) {
	content := []byte(`FROM alpine:3.18
EXPOSE 443/tcp
`)
	s := NewDockerfile()
	findings, err := s.ScanFile("Dockerfile", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "cbom-configfile-dockerfile-tls-port" {
			found = true
			if f.Severity != types.SeverityInfo {
				t.Errorf("expected info severity for EXPOSE 443, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected TLS port finding for EXPOSE 443/tcp")
	}
}

func TestDockerfileNonDockerfile(t *testing.T) {
	content := []byte(`
#!/bin/bash
echo "hello world"
apt-get install openssl
`)
	s := NewDockerfile()
	findings, err := s.ScanFile("script.sh", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-Dockerfile, got %d", len(findings))
	}
}

func TestDockerfileEmptyFile(t *testing.T) {
	s := NewDockerfile()
	findings, err := s.ScanFile("Dockerfile", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestDockerfileFilenameVariants(t *testing.T) {
	content := []byte("FROM ubuntu:22.04\nEXPOSE 443\n")

	tests := []struct {
		path     string
		expected bool
	}{
		{"Dockerfile", true},
		{"Dockerfile.prod", true},
		{"app.dockerfile", true},
		{"script.sh", false},
		{"main.go", false},
	}

	s := NewDockerfile()
	for _, tt := range tests {
		findings, err := s.ScanFile(tt.path, content)
		if err != nil {
			t.Fatalf("ScanFile(%q) returned error: %v", tt.path, err)
		}
		hasFindings := len(findings) > 0
		if hasFindings != tt.expected {
			t.Errorf("ScanFile(%q): expected findings=%v, got %v", tt.path, tt.expected, hasFindings)
		}
	}
}
