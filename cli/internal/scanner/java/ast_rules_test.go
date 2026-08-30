package java

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active Java tables and that passing "" restores the embedded
// set. Global state is restored via t.Cleanup so other java tests are unaffected.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := jcaClassInfo["MessageDigest"]; !ok {
		t.Fatal("embedded jcaClassInfo missing MessageDigest — test precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: java\n" +
		"jca_classes:\n  - { class: Cipher, primitive: block-cipher, rule_tag: cipher }\n" +
		"algorithm_families:\n  - { name: AES, family: aes }\n"
	if err := os.WriteFile(filepath.Join(dir, "java.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := jcaClassInfo["MessageDigest"]; ok {
		t.Error("external rules should have replaced the tables; MessageDigest still present")
	}
	if _, ok := jcaClassInfo["Cipher"]; !ok {
		t.Error("external Cipher entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := jcaClassInfo["MessageDigest"]; !ok {
		t.Error("restoring embedded tables failed; MessageDigest absent")
	}
}
