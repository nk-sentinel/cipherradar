package fingerprint

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// --- Normalize tests ---

func TestNormalize_JavaCipherGetInstance(t *testing.T) {
	input := `cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")`
	expected := `_VAR_ = Cipher.getInstance(_STR_)`
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_StripComments(t *testing.T) {
	input := "md5 = hashlib.md5() // create hash\n"
	expected := "_VAR_ = hashlib.md5()"
	result := Normalize(input, "python")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_StripHashComments(t *testing.T) {
	input := "md5 = hashlib.md5() # create hash\n"
	expected := "_VAR_ = hashlib.md5()"
	result := Normalize(input, "python")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_StripBlockComments(t *testing.T) {
	input := "Cipher.getInstance(/* mode */ \"AES\")"
	expected := "Cipher.getInstance(_STR_)"
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_CollapseWhitespace(t *testing.T) {
	input := "  Cipher   cipher =\n    Cipher.getInstance(  \"AES\"  );"
	expected := "_VAR_ = Cipher.getInstance(_STR_);"
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_NumericLiterals(t *testing.T) {
	input := `KeyGenerator.getInstance("AES", 256)`
	expected := `KeyGenerator.getInstance(_STR_, _NUM_)`
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_PythonHashlib(t *testing.T) {
	input := `digest = hashlib.sha256(data)`
	expected := `_VAR_ = hashlib.sha256(_VAR_)`
	result := Normalize(input, "python")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_PythonCryptography(t *testing.T) {
	input := `cipher = Cipher(algorithms.AES(key), modes.CBC(iv))`
	expected := `_VAR_ = Cipher(algorithms.AES(_VAR_), modes.CBC(_VAR_))`
	result := Normalize(input, "python")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_GoCryptoImport(t *testing.T) {
	input := `h := sha256.New()`
	expected := `_VAR_ := sha256.New()`
	result := Normalize(input, "go")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_GoCryptoAES(t *testing.T) {
	input := `block, err := aes.NewCipher(key)`
	expected := `_VAR_, _VAR_ := aes.NewCipher(_VAR_)`
	result := Normalize(input, "go")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_JSCryptoCreateHash(t *testing.T) {
	input := `const hash = crypto.createHash('sha256')`
	expected := `_VAR_ = crypto.createHash(_STR_)`
	result := Normalize(input, "javascript")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_JSLetDecl(t *testing.T) {
	input := `let cipher = crypto.createCipheriv('aes-256-cbc', key, iv)`
	expected := `_VAR_ = crypto.createCipheriv(_STR_, _VAR_, _VAR_)`
	result := Normalize(input, "javascript")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_PreserveFunctionCalls(t *testing.T) {
	input := `MessageDigest.getInstance("SHA-256")`
	expected := `MessageDigest.getInstance(_STR_)`
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_HexLiterals(t *testing.T) {
	input := `keySize = 0x100`
	expected := `_VAR_ = _NUM_`
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_FloatLiterals(t *testing.T) {
	input := `timeout = 3.14`
	expected := `_VAR_ = _NUM_`
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_SingleQuotedStrings(t *testing.T) {
	input := `algo = 'AES'`
	expected := `_VAR_ = _STR_`
	result := Normalize(input, "python")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_BacktickStrings(t *testing.T) {
	input := "algo = `AES-256`"
	expected := `_VAR_ = _STR_`
	result := Normalize(input, "javascript")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_EmptyInput(t *testing.T) {
	result := Normalize("", "java")
	if result != "" {
		t.Errorf("got %q, want %q", result, "")
	}
}

func TestNormalize_NoVarDeclaration(t *testing.T) {
	// Pure function call with no assignment — should not be altered beyond string normalization
	input := `Cipher.getInstance("AES")`
	expected := `Cipher.getInstance(_STR_)`
	result := Normalize(input, "java")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestNormalize_UnknownLanguage(t *testing.T) {
	// Should still do basic normalization (whitespace, comments, strings, numbers, variables)
	input := `  x = "hello"  // comment`
	expected := `_VAR_ = _STR_`
	result := Normalize(input, "unknown")
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

// --- ComputeFingerprint tests ---

func TestFingerprint_SameCodeDifferentFormatting(t *testing.T) {
	f1 := types.Finding{
		RuleID:   "cbom-java-weak-cipher",
		Location: types.Location{File: "src/Crypto.java", Snippet: `Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`},
	}
	f2 := types.Finding{
		RuleID:   "cbom-java-weak-cipher",
		Location: types.Location{File: "src/Crypto.java", Snippet: "Cipher  aesCipher =\n    Cipher.getInstance( \"AES/ECB/PKCS5Padding\" );"},
	}
	fp1 := ComputeFingerprint(&f1, "java")
	fp2 := ComputeFingerprint(&f2, "java")
	if fp1 != fp2 {
		t.Errorf("same code different formatting should produce same fingerprint:\n  fp1=%s (norm=%q)\n  fp2=%s (norm=%q)",
			fp1, f1.NormalizedSignature, fp2, f2.NormalizedSignature)
	}
}

func TestFingerprint_DifferentFiles(t *testing.T) {
	f1 := types.Finding{RuleID: "cbom-java-weak-cipher", Location: types.Location{File: "src/A.java", Snippet: `Cipher.getInstance("AES")`}}
	f2 := types.Finding{RuleID: "cbom-java-weak-cipher", Location: types.Location{File: "src/B.java", Snippet: `Cipher.getInstance("AES")`}}
	fp1 := ComputeFingerprint(&f1, "java")
	fp2 := ComputeFingerprint(&f2, "java")
	if fp1 == fp2 {
		t.Errorf("different files should produce different fingerprints")
	}
}

func TestFingerprint_DifferentRuleIDs(t *testing.T) {
	f1 := types.Finding{RuleID: "cbom-java-weak-cipher", Location: types.Location{File: "src/A.java", Snippet: `Cipher.getInstance("AES")`}}
	f2 := types.Finding{RuleID: "cbom-java-insecure-hash", Location: types.Location{File: "src/A.java", Snippet: `Cipher.getInstance("AES")`}}
	fp1 := ComputeFingerprint(&f1, "java")
	fp2 := ComputeFingerprint(&f2, "java")
	if fp1 == fp2 {
		t.Errorf("different rule IDs should produce different fingerprints")
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	f := types.Finding{
		RuleID:   "cbom-python-hashlib",
		Location: types.Location{File: "lib/crypto.py", Snippet: `h = hashlib.md5()`},
	}
	fp1 := ComputeFingerprint(&f, "python")
	fp2 := ComputeFingerprint(&f, "python")
	if fp1 != fp2 {
		t.Errorf("fingerprint must be deterministic: %s vs %s", fp1, fp2)
	}
}

func TestFingerprint_SetsNormalizedSignature(t *testing.T) {
	f := types.Finding{
		RuleID:   "cbom-go-crypto",
		Location: types.Location{File: "main.go", Snippet: `h := sha256.New()`},
	}
	ComputeFingerprint(&f, "go")
	if f.NormalizedSignature == "" {
		t.Error("NormalizedSignature should be set after ComputeFingerprint")
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint should be set after ComputeFingerprint")
	}
}

func TestFingerprint_SHA256Format(t *testing.T) {
	f := types.Finding{
		RuleID:   "cbom-java-weak-cipher",
		Location: types.Location{File: "src/Crypto.java", Snippet: `Cipher.getInstance("AES")`},
	}
	fp := ComputeFingerprint(&f, "java")
	// SHA-256 hex digest is 64 characters
	if len(fp) != 64 {
		t.Errorf("fingerprint should be 64-char SHA-256 hex digest, got length %d: %s", len(fp), fp)
	}
}

func TestFingerprint_EmptySnippet(t *testing.T) {
	f := types.Finding{
		RuleID:   "cbom-java-weak-cipher",
		Location: types.Location{File: "src/Crypto.java", Snippet: ""},
	}
	fp := ComputeFingerprint(&f, "java")
	// Even with empty snippet, should produce a valid fingerprint
	if len(fp) != 64 {
		t.Errorf("fingerprint should be 64-char even with empty snippet, got length %d", len(fp))
	}
}

// --- Language detection from file path ---

func TestLanguageFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"src/Crypto.java", "java"},
		{"lib/crypto.py", "python"},
		{"main.go", "go"},
		{"app.js", "javascript"},
		{"app.ts", "javascript"},
		{"app.tsx", "javascript"},
		{"lib.rs", "rust"},
		{"code.cpp", "cpp"},
		{"code.c", "cpp"},
		{"code.cs", "csharp"},
		{"code.rb", "ruby"},
		{"code.swift", "swift"},
		{"code.kt", "kotlin"},
		{"code.php", "php"},
		{"code.dart", "dart"},
		{"unknown.xyz", ""},
	}
	for _, tt := range tests {
		got := LanguageFromPath(tt.path)
		if got != tt.want {
			t.Errorf("LanguageFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
