package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestAdminCmdExists(t *testing.T) {
	// Verify the admin command is registered on rootCmd
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "admin" {
			found = true
			// Verify reset-password subcommand exists
			subFound := false
			for _, sub := range c.Commands() {
				if sub.Name() == "reset-password" {
					subFound = true
					break
				}
			}
			if !subFound {
				t.Error("admin command missing reset-password subcommand")
			}
			break
		}
	}
	if !found {
		t.Error("admin command not registered on rootCmd")
	}
}

func TestAdminResetPasswordOutput(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"admin", "reset-password", "--email", "admin@example.com"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should contain the email
	if !strings.Contains(output, "admin@example.com") {
		t.Error("output should contain the email address")
	}

	// Should contain an UPDATE SQL statement
	if !strings.Contains(output, "UPDATE users SET") {
		t.Error("output should contain SQL UPDATE statement")
	}

	// Should contain a temporary password
	if !strings.Contains(output, "Temporary password") && !strings.Contains(output, "temporary password") {
		t.Error("output should contain a temporary password")
	}

	// Should warn about changing password
	if !strings.Contains(output, "IMPORTANT") {
		t.Error("output should contain IMPORTANT warning")
	}
}

func TestGenerateTempPassword(t *testing.T) {
	p1, err := generateTempPassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p1) != 24 {
		t.Errorf("expected 24-char hex password, got %d chars", len(p1))
	}

	// Should generate unique passwords
	p2, _ := generateTempPassword()
	if p1 == p2 {
		t.Error("two generated passwords should be different")
	}
}
