package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompletion_GeneratesNonEmptyScripts(t *testing.T) {
	cases := map[string]string{
		// shell name -> fragment we expect to find in the generated script
		"bash":       "__cradar",
		"zsh":        "#compdef",
		"fish":       "cradar",
		"powershell": "Register-ArgumentCompleter",
	}
	for shell, marker := range cases {
		t.Run(shell, func(t *testing.T) {
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			rootCmd.SetArgs([]string{"completion", shell})
			defer func() {
				rootCmd.SetArgs(nil)
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
			}()

			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("completion %s: %v", shell, err)
			}
			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("completion %s produced empty output", shell)
			}
			if !strings.Contains(out, marker) {
				t.Errorf("completion %s missing expected marker %q; got first 120 chars: %q",
					shell, marker, firstN(out, 120))
			}
		})
	}
}

func TestCompletion_RejectsUnknownShell(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"completion", "tcsh"})
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected error for unsupported shell")
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
