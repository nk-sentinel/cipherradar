package kdf

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestCheckKDFIterations(t *testing.T) {
	tests := []struct {
		name       string
		algorithm  string
		iterations int
		wantSev    types.Severity
		wantMsg    bool // true if message should be non-empty
	}{
		{"pbkdf2 low iterations", "pbkdf2", 1000, types.SeverityMedium, true},
		{"pbkdf2 borderline low", "pbkdf2", 99999, types.SeverityMedium, true},
		{"pbkdf2 at minimum", "pbkdf2", 100000, types.SeverityInfo, false},
		{"pbkdf2 above minimum", "pbkdf2", 600000, types.SeverityInfo, false},
		{"bcrypt low cost", "bcrypt", 4, types.SeverityMedium, true},
		{"bcrypt borderline low", "bcrypt", 9, types.SeverityMedium, true},
		{"bcrypt at minimum", "bcrypt", 10, types.SeverityInfo, false},
		{"bcrypt above minimum", "bcrypt", 14, types.SeverityInfo, false},
		{"unknown algo", "argon2", 1, types.SeverityInfo, false},
		{"zero iterations", "pbkdf2", 0, types.SeverityInfo, false},
		{"negative iterations", "pbkdf2", -1, types.SeverityInfo, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, msg := CheckKDFIterations(tt.algorithm, tt.iterations)
			if sev != tt.wantSev {
				t.Errorf("severity = %s, want %s", sev, tt.wantSev)
			}
			if tt.wantMsg && msg == "" {
				t.Error("expected non-empty message")
			}
			if !tt.wantMsg && msg != "" {
				t.Errorf("expected empty message, got %q", msg)
			}
		})
	}
}
