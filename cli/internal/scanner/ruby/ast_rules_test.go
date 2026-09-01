package ruby

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active Ruby tables and that passing "" restores the embedded set.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := cipherAlgoMap["aes-128-cbc"]; !ok {
		t.Fatal("embedded cipherAlgoMap missing aes-128-cbc — precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: ruby\n" +
		"cipher_algorithms:\n  - { method: aes-256-gcm, family: aes, mode: gcm, name: AES-256-GCM }\n" +
		"digest_algorithms:\n  - { key: sha256, family: sha-256, name: SHA-256 }\n"
	if err := os.WriteFile(filepath.Join(dir, "ruby.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := cipherAlgoMap["aes-128-cbc"]; ok {
		t.Error("external rules should have replaced the tables; aes-128-cbc still present")
	}
	if _, ok := cipherAlgoMap["aes-256-gcm"]; !ok {
		t.Error("external aes-256-gcm entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := cipherAlgoMap["aes-128-cbc"]; !ok {
		t.Error("restoring embedded tables failed; aes-128-cbc absent")
	}
}
