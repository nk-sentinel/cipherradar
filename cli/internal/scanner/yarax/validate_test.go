package yarax

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRulesDir(t *testing.T) {
	valid := t.TempDir()
	if err := os.WriteFile(filepath.Join(valid, "r.yar"), []byte("rule x { condition: true }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()

	cases := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{"valid dir with .yar", valid, false},
		{"empty dir (no rules)", empty, true},
		{"nonexistent dir", filepath.Join(valid, "nope"), true},
		{"empty string", "", true},
		{"whitespace", "   ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRulesDir(tc.dir)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateRulesDir(%q): expected error, got nil", tc.dir)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateRulesDir(%q): unexpected error: %v", tc.dir, err)
			}
		})
	}
}
