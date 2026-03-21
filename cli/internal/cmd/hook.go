package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

// hookScript is the pre-commit hook content installed by `cradar hook install`.
const hookScript = `#!/bin/sh
# CipherRadar pre-commit hook
cradar scan --fast --staged-only --fail-on critical
`

// hookMarker identifies a CipherRadar-installed hook for safe uninstall.
const hookMarker = "# CipherRadar pre-commit hook"

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Manage git pre-commit hooks",
}

var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install a git pre-commit hook that runs CipherRadar on staged files",
	Long: `Install a CipherRadar pre-commit hook that scans staged files for
cryptographic assets before each commit.

  cradar hook install          # install to .git/hooks/pre-commit
  cradar hook install --global # install as a git global hook`,
	RunE: runHookInstall,
}

var hookUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the CipherRadar pre-commit hook",
	RunE:  runHookUninstall,
}

func init() {
	hookInstallCmd.Flags().Bool("global", false, "install as git global hook")
	hookUninstallCmd.Flags().Bool("global", false, "uninstall git global hook")

	hookCmd.AddCommand(hookInstallCmd)
	hookCmd.AddCommand(hookUninstallCmd)
	rootCmd.AddCommand(hookCmd)
}

// runHookInstall installs the CipherRadar pre-commit hook.
func runHookInstall(cmd *cobra.Command, _ []string) error {
	global, _ := cmd.Flags().GetBool("global")

	hookDir, err := resolveHookDir(global)
	if err != nil {
		return err
	}

	// Create the hooks directory if it does not exist.
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		return fmt.Errorf("creating hooks directory %s: %w", hookDir, err)
	}

	hookPath := filepath.Join(hookDir, "pre-commit")

	// Check whether a pre-commit hook already exists.
	if _, err := os.Stat(hookPath); err == nil {
		// Read existing content to see if it is ours.
		existing, readErr := os.ReadFile(hookPath)
		if readErr != nil {
			return fmt.Errorf("reading existing hook %s: %w", hookPath, readErr)
		}
		if !containsMarker(existing) {
			return fmt.Errorf("a pre-commit hook already exists at %s (not installed by CipherRadar); remove it first or use a hook manager", hookPath)
		}
		// It is ours — overwrite below.
	}

	if err := os.WriteFile(hookPath, []byte(hookScript), 0o755); err != nil {
		return fmt.Errorf("writing hook to %s: %w", hookPath, err)
	}

	scope := "local"
	if global {
		scope = "global"
		// Set the global core.hooksPath so git uses this directory.
		if err := setGlobalHooksPath(hookDir); err != nil {
			return fmt.Errorf("setting git global hooksPath: %w", err)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CipherRadar pre-commit hook installed (%s): %s\n", scope, hookPath)
	return nil
}

// runHookUninstall removes the CipherRadar pre-commit hook.
func runHookUninstall(cmd *cobra.Command, _ []string) error {
	global, _ := cmd.Flags().GetBool("global")

	hookDir, err := resolveHookDir(global)
	if err != nil {
		return err
	}

	hookPath := filepath.Join(hookDir, "pre-commit")

	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(cmd.OutOrStdout(), "No pre-commit hook found; nothing to uninstall.")
			return nil
		}
		return fmt.Errorf("reading hook %s: %w", hookPath, err)
	}

	if !containsMarker(existing) {
		return fmt.Errorf("the pre-commit hook at %s was not installed by CipherRadar; refusing to remove", hookPath)
	}

	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("removing hook %s: %w", hookPath, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CipherRadar pre-commit hook removed: %s\n", hookPath)
	return nil
}

// resolveHookDir returns the hooks directory path for local or global scope.
func resolveHookDir(global bool) (string, error) {
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determining home directory: %w", err)
		}
		return filepath.Join(home, ".config", "git", "hooks"), nil
	}

	// Local: find the .git directory for the current repository.
	gitDir, err := findGitDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(gitDir, "hooks"), nil
}

// findGitDir locates the .git directory starting from the current working
// directory and walking upward.
func findGitDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	for {
		candidate := filepath.Join(dir, ".git")
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("not a git repository (no .git directory found)")
}

// containsMarker returns true if the content contains the CipherRadar hook marker.
func containsMarker(content []byte) bool {
	return len(content) > 0 && contains(string(content), hookMarker)
}

// contains is a simple string-contains check.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// setGlobalHooksPath sets git's global core.hooksPath to the given directory.
func setGlobalHooksPath(dir string) error {
	cmd := exec.Command("git", "config", "--global", "core.hooksPath", dir)
	return cmd.Run()
}
