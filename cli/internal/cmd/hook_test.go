package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Hook install tests
// ---------------------------------------------------------------------------

func TestHookInstall_CreatesPreCommitHook(t *testing.T) {
	// Set up a fake git repo.
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Change to the temp dir so findGitDir works.
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// Run the install command.
	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"hook", "install"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hook install failed: %v", err)
	}

	// Verify the hook file was created.
	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook file: %v", err)
	}

	// Verify content.
	if !strings.Contains(string(content), hookMarker) {
		t.Error("hook file does not contain CipherRadar marker")
	}
	if !strings.Contains(string(content), "cradar scan --fast --staged-only --fail-on critical") {
		t.Error("hook file does not contain scan command")
	}

	// Verify the file is executable.
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("hook file should be executable")
	}
}

func TestHookInstall_RefusesToOverwriteForeignHook(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write a foreign pre-commit hook.
	foreignHook := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(foreignHook, []byte("#!/bin/sh\necho foreign\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"hook", "install"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when foreign hook exists")
	}
	if !strings.Contains(err.Error(), "not installed by CipherRadar") {
		t.Errorf("expected 'not installed by CipherRadar' error, got: %v", err)
	}
}

func TestHookInstall_OverwritesOwnHook(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write a CipherRadar hook (old version).
	ourHook := filepath.Join(hooksDir, "pre-commit")
	oldContent := "#!/bin/sh\n" + hookMarker + "\ncradar scan --staged-only\n"
	if err := os.WriteFile(ourHook, []byte(oldContent), 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"hook", "install"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hook install should overwrite own hook: %v", err)
	}

	// Verify it was updated.
	content, err := os.ReadFile(ourHook)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "--fast") {
		t.Error("hook should contain --fast flag after reinstall")
	}
}

// ---------------------------------------------------------------------------
// Hook uninstall tests
// ---------------------------------------------------------------------------

func TestHookUninstall_RemovesCipherRadarHook(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"hook", "uninstall"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hook uninstall failed: %v", err)
	}

	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Error("hook file should have been removed")
	}
}

func TestHookUninstall_RefusesToRemoveForeignHook(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho foreign\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"hook", "uninstall"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when uninstalling foreign hook")
	}
	if !strings.Contains(err.Error(), "not installed by CipherRadar") {
		t.Errorf("expected 'not installed by CipherRadar' error, got: %v", err)
	}

	// Verify the foreign hook was NOT removed.
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		t.Error("foreign hook should NOT have been removed")
	}
}

func TestHookUninstall_NoHookPresent(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"hook", "uninstall"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hook uninstall should succeed when no hook exists: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "nothing to uninstall") {
		t.Errorf("expected 'nothing to uninstall' message, got: %s", output)
	}
}

// ---------------------------------------------------------------------------
// Hook command registration
// ---------------------------------------------------------------------------

func TestHookCommandRegistered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "hook" {
			found = true
			// Check subcommands.
			subNames := make(map[string]bool)
			for _, sub := range cmd.Commands() {
				subNames[sub.Name()] = true
			}
			if !subNames["install"] {
				t.Error("hook command missing 'install' subcommand")
			}
			if !subNames["uninstall"] {
				t.Error("hook command missing 'uninstall' subcommand")
			}
			break
		}
	}
	if !found {
		t.Error("expected 'hook' command to be registered on root")
	}
}

// ---------------------------------------------------------------------------
// containsMarker helper test
// ---------------------------------------------------------------------------

func TestContainsMarker(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"empty", "", false},
		{"foreign hook", "#!/bin/sh\necho hello\n", false},
		{"our hook", hookScript, true},
		{"marker only", hookMarker, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsMarker([]byte(tt.content))
			if got != tt.want {
				t.Errorf("containsMarker(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}
