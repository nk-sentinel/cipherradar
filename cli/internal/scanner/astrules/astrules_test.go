package astrules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadJava_Embedded(t *testing.T) {
	tbl, err := LoadJava("")
	if err != nil {
		t.Fatalf("LoadJava(embedded): %v", err)
	}
	// Guard against silent drift in the embedded data (counts mirror the
	// former hardcoded Go maps).
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"jca_classes", len(tbl.JCAClasses), 10},
		{"algorithm_families", len(tbl.AlgorithmFamilies), 26},
		{"bc_engines", len(tbl.BCEngines), 7},
		{"bc_asymmetric", len(tbl.BCAsymmetric), 13},
		{"bc_modes", len(tbl.BCModes), 8},
		{"bc_digests", len(tbl.BCDigests), 10},
		{"ssl_protocols", len(tbl.SSLProtocols), 8},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("embedded %s: got %d entries, want %d", c.name, c.got, c.want)
		}
	}
	if tbl.Language != "java" {
		t.Errorf("language = %q, want java", tbl.Language)
	}
}

func TestLoadGo_Embedded(t *testing.T) {
	tbl, err := LoadGo("")
	if err != nil {
		t.Fatalf("LoadGo(embedded): %v", err)
	}
	if len(tbl.TLSVersions) != 5 {
		t.Errorf("embedded tls_versions: got %d, want 5", len(tbl.TLSVersions))
	}
	if len(tbl.SM2Functions) != 5 {
		t.Errorf("embedded sm2_functions: got %d, want 5", len(tbl.SM2Functions))
	}
	if tbl.Language != "go" {
		t.Errorf("language = %q, want go", tbl.Language)
	}
}

func TestLoadJava_ExternalReplacesEmbedded(t *testing.T) {
	dir := t.TempDir()
	// A minimal but valid external file — only two jca classes.
	yml := `version: 1
language: java
jca_classes:
  - { class: Cipher, primitive: block-cipher, rule_tag: cipher }
algorithm_families:
  - { name: AES, family: aes }
`
	if err := os.WriteFile(filepath.Join(dir, "java.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	tbl, err := LoadJava(dir)
	if err != nil {
		t.Fatalf("LoadJava(external): %v", err)
	}
	if len(tbl.JCAClasses) != 1 || tbl.JCAClasses[0].Class != "Cipher" {
		t.Errorf("external file not used: %+v", tbl.JCAClasses)
	}
	if len(tbl.BCEngines) != 0 {
		t.Errorf("external replace should not inherit embedded bc_engines, got %d", len(tbl.BCEngines))
	}
}

func TestLoadJava_ExternalDirWithoutJavaFile_FallsBackToEmbedded(t *testing.T) {
	dir := t.TempDir() // no java.yml
	tbl, err := LoadJava(dir)
	if err != nil {
		t.Fatalf("LoadJava(dir without java.yml): %v", err)
	}
	if len(tbl.JCAClasses) != 10 {
		t.Errorf("per-language fallback failed: got %d jca classes, want embedded 10", len(tbl.JCAClasses))
	}
}

func TestValidateRulesDir(t *testing.T) {
	valid := t.TempDir()
	if err := os.WriteFile(filepath.Join(valid, "java.yml"),
		[]byte("version: 1\nlanguage: java\njca_classes:\n  - { class: Cipher, primitive: block-cipher, rule_tag: cipher }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	unrelated := t.TempDir()
	if err := os.WriteFile(filepath.Join(unrelated, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	malformed := t.TempDir()
	if err := os.WriteFile(filepath.Join(malformed, "java.yml"), []byte("jca_classes: [ this is : not : valid"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{"valid java.yml", valid, false},
		{"empty dir", empty, true},
		{"dir without <lang>.yml", unrelated, true},
		{"malformed java.yml", malformed, true},
		{"empty string", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRulesDir(c.dir)
			if c.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
