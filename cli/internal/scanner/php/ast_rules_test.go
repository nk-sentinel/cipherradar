package php

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active PHP tables and that passing "" restores the embedded set.
// Global state is restored via t.Cleanup so other php tests are unaffected.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := hashAlgoMap["md5"]; !ok {
		t.Fatal("embedded hashAlgoMap missing md5 — test precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: php\n" +
		"openssl_funcs:\n  - { func: openssl_encrypt, primitive: block-cipher, crypto_funcs: [encrypt], method_arg_idx: 1, is_key_gen: false }\n" +
		"hash_algos:\n  - { algo: sha256, family: sha-256, name: \"SHA-256\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "php.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := hashAlgoMap["md5"]; ok {
		t.Error("external rules should have replaced the tables; md5 still present")
	}
	if _, ok := hashAlgoMap["sha256"]; !ok {
		t.Error("external sha256 entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := hashAlgoMap["md5"]; !ok {
		t.Error("restoring embedded tables failed; md5 absent")
	}
}
