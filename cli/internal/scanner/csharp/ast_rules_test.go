package csharp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active C# tables and that passing "" restores the embedded set.
// Global state is restored via t.Cleanup so other csharp tests are unaffected.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := dotNetFactoryClasses["MD5"]; !ok {
		t.Fatal("embedded dotNetFactoryClasses missing MD5 — test precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: csharp\n" +
		"factory_classes:\n  - { class: Aes, family: aes, name: AES, primitive: block-cipher, severity: info, rule_tag: aes, crypto_func: encrypt }\n"
	if err := os.WriteFile(filepath.Join(dir, "csharp.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := dotNetFactoryClasses["MD5"]; ok {
		t.Error("external rules should have replaced the tables; MD5 still present")
	}
	if _, ok := dotNetFactoryClasses["Aes"]; !ok {
		t.Error("external Aes entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := dotNetFactoryClasses["MD5"]; !ok {
		t.Error("restoring embedded tables failed; MD5 absent")
	}
}
