package cpp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active C/C++ tables and that passing "" restores the embedded
// set.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := tlsMethodMap["TLS_method"]; !ok {
		t.Fatal("embedded tlsMethodMap missing TLS_method — precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: cpp\n" +
		"asym_funcs:\n  - { func: DSA_generate_key, family: dsa, name: DSA, primitive: signature, fn: generate }\n" +
		"tls_methods:\n  - { method: TLSv1_3_method, name: \"TLS 1.3\", version: \"1.3\", severity: info }\n" +
		"tls_version_constants:\n  - { const: TLS1_3_VERSION, name: \"TLS 1.3\", version: \"1.3\", severity: info }\n"
	if err := os.WriteFile(filepath.Join(dir, "cpp.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := tlsMethodMap["TLS_method"]; ok {
		t.Error("external rules should have replaced the tables; TLS_method still present")
	}
	if _, ok := tlsMethodMap["TLSv1_3_method"]; !ok {
		t.Error("external TLSv1_3_method entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := tlsMethodMap["TLS_method"]; !ok {
		t.Error("restoring embedded tables failed; TLS_method absent")
	}
}
