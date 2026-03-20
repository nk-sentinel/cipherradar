package configfile

import (
	"os"
	"strings"
	"testing"
)

func TestJavaSecurityName(t *testing.T) {
	s := NewJavaSecurity()
	if s.Name() != "java-security" {
		t.Errorf("expected name 'java-security', got %q", s.Name())
	}
}

func TestJavaSecurityExtensions(t *testing.T) {
	s := NewJavaSecurity()
	exts := s.Extensions()
	if len(exts) != 1 || exts[0] != ".security" {
		t.Errorf("expected [.security], got %v", exts)
	}
}

func TestJavaSecurityScanFile(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/java.security")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewJavaSecurity()
	findings, err := s.ScanFile("java.security", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// The test fixture has a good disabled list that includes most weak algorithms.
	// Findings should only be for algorithms that are NOT in the disabled list.
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("expected Pass=1 for %q, got %d", f.Name, f.Pass)
		}
		if !strings.HasPrefix(f.RuleID, "cbom-configfile-java-") {
			t.Errorf("expected rule ID starting with cbom-configfile-java-, got %q", f.RuleID)
		}
	}
}

func TestJavaSecurityWeakConfig(t *testing.T) {
	// A config where the disabled list is too permissive (missing many algorithms).
	content := []byte(`
jdk.tls.disabledAlgorithms=SSLv3
jdk.certpath.disabledAlgorithms=MD2
`)

	s := NewJavaSecurity()
	findings, err := s.ScanFile("weak.security", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// Should flag missing disabled algorithms.
	if len(findings) == 0 {
		t.Fatal("expected findings for weak config, got none")
	}

	// Verify specific missing algorithms are reported.
	missingNames := make(map[string]bool)
	for _, f := range findings {
		missingNames[f.Name] = true
	}

	expected := []string{"MD5", "RC4", "DES", "TLSv1", "TLSv1.1"}
	for _, algo := range expected {
		found := false
		for name := range missingNames {
			if strings.Contains(name, algo) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected finding for missing disabled algorithm %q", algo)
		}
	}
}

func TestJavaSecurityEmptyFile(t *testing.T) {
	s := NewJavaSecurity()
	findings, err := s.ScanFile("empty.security", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestJavaSecurityContinuationLines(t *testing.T) {
	// Test that backslash continuation lines are properly joined.
	content := []byte(`jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, \
    DH keySize < 2048, EC keySize < 224, 3DES_EDE_CBC, anon, NULL
`)
	s := NewJavaSecurity()
	findings, err := s.ScanFile("continuation.security", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	// MD5 (as a standalone) is not in the disabled list (only MD5withRSA is).
	// RC4, DES, SSLv3, TLSv1, TLSv1.1 are all disabled.
	for _, f := range findings {
		if strings.Contains(f.Name, "RC4") {
			t.Errorf("RC4 should be disabled in this config but reported as missing: %s", f.Name)
		}
		if strings.Contains(f.Name, "SSLv3") {
			t.Errorf("SSLv3 should be disabled in this config but reported as missing: %s", f.Name)
		}
	}
}
