package javascript

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active JavaScript tables and that passing "" restores the
// embedded set. Global state is restored via t.Cleanup so other javascript
// tests are unaffected.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := hashAlgorithms["md5"]; !ok {
		t.Fatal("embedded hashAlgorithms missing md5 — test precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: javascript\n" +
		"hash_algorithms:\n  - { token: blake2, family: blake2, name: BLAKE2 }\n" +
		"cipher_algorithms:\n  - { token: aes-256-gcm, family: aes, name: AES-256-GCM, mode: gcm, primitive: ae, key_size: 256 }\n"
	if err := os.WriteFile(filepath.Join(dir, "javascript.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := hashAlgorithms["md5"]; ok {
		t.Error("external rules should have replaced the tables; md5 still present")
	}
	if _, ok := hashAlgorithms["blake2"]; !ok {
		t.Error("external blake2 entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := hashAlgorithms["md5"]; !ok {
		t.Error("restoring embedded tables failed; md5 absent")
	}
}
