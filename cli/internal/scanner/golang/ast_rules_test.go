package golang

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active Go tables and that passing "" restores the embedded set.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := tlsVersionConstants["VersionTLS10"]; !ok {
		t.Fatal("embedded tlsVersionConstants missing VersionTLS10 — precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: go\n" +
		"tls_versions:\n  - { const: VersionTLS13, name: \"TLS 1.3\", version: \"1.3\", severity: info }\n" +
		"sm2_functions:\n  - { func: Sign, crypto_fn: sign, primitive: signature }\n"
	if err := os.WriteFile(filepath.Join(dir, "go.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := tlsVersionConstants["VersionTLS10"]; ok {
		t.Error("external rules should have replaced the tables; VersionTLS10 still present")
	}
	if _, ok := tlsVersionConstants["VersionTLS13"]; !ok {
		t.Error("external VersionTLS13 entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := tlsVersionConstants["VersionTLS10"]; !ok {
		t.Error("restoring embedded tables failed; VersionTLS10 absent")
	}
}
