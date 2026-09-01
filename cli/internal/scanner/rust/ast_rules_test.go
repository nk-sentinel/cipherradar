package rust

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active Rust tables and that passing "" restores the embedded
// set. Global state is restored via t.Cleanup so other rust tests are unaffected.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := ringDigestAlgorithms["SHA256"]; !ok {
		t.Fatal("embedded ringDigestAlgorithms missing SHA256 — test precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: rust\n" +
		"ring_digest_algorithms:\n  - { id: SHA512, name: SHA-512, family: sha-512, severity: info }\n" +
		"rustcrypto_aes_gcm:\n  - { cipher: Aes128Gcm, name: AES-128-GCM, key_size: 128 }\n"
	if err := os.WriteFile(filepath.Join(dir, "rust.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := ringDigestAlgorithms["SHA256"]; ok {
		t.Error("external rules should have replaced the tables; SHA256 still present")
	}
	if _, ok := ringDigestAlgorithms["SHA512"]; !ok {
		t.Error("external SHA512 entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := ringDigestAlgorithms["SHA256"]; !ok {
		t.Error("restoring embedded tables failed; SHA256 absent")
	}
}
