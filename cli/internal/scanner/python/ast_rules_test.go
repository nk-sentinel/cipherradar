package python

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active Python tables and that passing "" restores the embedded
// set. Global state is restored via t.Cleanup so other python tests are unaffected.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := hashlibMethodAlgorithms["md5"]; !ok {
		t.Fatal("embedded hashlibMethodAlgorithms missing md5 — test precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: python\n" +
		"hashlib_method_algorithms:\n  - { key: whirlpool, value: whirlpool }\n"
	if err := os.WriteFile(filepath.Join(dir, "python.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := hashlibMethodAlgorithms["md5"]; ok {
		t.Error("external rules should have replaced the tables; md5 still present")
	}
	if _, ok := hashlibMethodAlgorithms["whirlpool"]; !ok {
		t.Error("external whirlpool entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := hashlibMethodAlgorithms["md5"]; !ok {
		t.Error("restoring embedded tables failed; md5 absent")
	}
}
