package swift

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyExternalRules_RoundTrip verifies that an external --ast-rules-dir
// replaces the active Swift tables and that passing "" restores the embedded set.
func TestApplyExternalRules_RoundTrip(t *testing.T) {
	if _, ok := ccCryptAlgConst["kCCAlgorithmDES"]; !ok {
		t.Fatal("embedded ccCryptAlgConst missing kCCAlgorithmDES — precondition broken")
	}
	t.Cleanup(func() { _ = ApplyExternalRules("") })

	dir := t.TempDir()
	yml := "version: 1\nlanguage: swift\n" +
		"cc_crypt_algorithms:\n" +
		"  - { const: kCCAlgorithmAES, family: aes, name: CCCrypt-AES, primitive: block-cipher, severity: info, rule_id: cbom-swift-commoncrypto-cccrypt-aes, crypto_funcs: [encrypt, decrypt], asset_type: algorithm }\n"
	if err := os.WriteFile(filepath.Join(dir, "swift.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyExternalRules(dir); err != nil {
		t.Fatalf("ApplyExternalRules(dir): %v", err)
	}
	if _, ok := ccCryptAlgConst["kCCAlgorithmDES"]; ok {
		t.Error("external rules should have replaced the tables; kCCAlgorithmDES still present")
	}
	if _, ok := ccCryptAlgConst["kCCAlgorithmAES"]; !ok {
		t.Error("external kCCAlgorithmAES entry missing after replace")
	}

	if err := ApplyExternalRules(""); err != nil {
		t.Fatalf("ApplyExternalRules(restore): %v", err)
	}
	if _, ok := ccCryptAlgConst["kCCAlgorithmDES"]; !ok {
		t.Error("restoring embedded tables failed; kCCAlgorithmDES absent")
	}
}
