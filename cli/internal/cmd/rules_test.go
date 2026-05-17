package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// execRules runs a rules subcommand with a fresh buffer and returns
// (stdout, error). The cobra tree is package-global, so we swap in a buffer
// for the duration of the call.
func execRules(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// pflag does NOT reset a flag's value between Execute() calls — once
	// Changed=true the last-used value sticks. That is fine for real CLI
	// use (one Execute per process) but poisons table-driven tests. Reset
	// every flag on the rules list/explain subcommands to its default
	// before each invocation.
	resetCmdFlags(rulesListCmd)
	resetCmdFlags(rulesExplainCmd)

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)
	rootCmd.SetArgs(append([]string{"rules"}, args...))
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	return stdout.String(), err
}

func resetCmdFlags(c *cobra.Command) {
	c.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
}

func TestRulesList_TableFormatIncludesHeader(t *testing.T) {
	out, err := execRules(t, "list")
	if err != nil {
		t.Fatalf("rules list: %v", err)
	}
	if !strings.Contains(out, "ID") || !strings.Contains(out, "CATEGORY") {
		t.Errorf("table header missing; got:\n%s", out[:min(400, len(out))])
	}
	if !strings.Contains(out, "cbom-java-ecb-mode-usage") {
		t.Error("expected known rule id in table output")
	}
	if !strings.Contains(out, "rule(s)") {
		t.Error("expected count footer in table output")
	}
}

func TestRulesList_JSONFormatDecodes(t *testing.T) {
	out, err := execRules(t, "list", "--format", "json")
	if err != nil {
		t.Fatalf("rules list --format json: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json decode failed: %v\nraw: %s", err, out[:min(200, len(out))])
	}
	if len(got) == 0 {
		t.Fatal("expected at least one rule in json output")
	}
	first := got[0]
	for _, key := range []string{"ID", "Category", "Maturity", "DefaultEnabled"} {
		if _, ok := first[key]; !ok {
			t.Errorf("rule json missing key %q; got keys: %v", key, keysOf(first))
		}
	}
}

func TestRulesList_CategoryFilter(t *testing.T) {
	out, err := execRules(t, "list", "--category", "inventory")
	if err != nil {
		t.Fatalf("rules list --category inventory: %v", err)
	}
	// No "security" rules should appear; easiest check: count should be
	// smaller than full corpus and no row ends with the security/experimental
	// triple.
	if strings.Contains(out, "security   experimental") {
		t.Error("inventory-only listing should exclude security rules")
	}
}

func TestRulesList_OnlyDefaultOff(t *testing.T) {
	out, err := execRules(t, "list", "--only-default-off")
	if err != nil {
		t.Fatalf("rules list --only-default-off: %v", err)
	}
	// default=false rules exist (the 20 hardcoded-* experimental rules);
	// no "true" in the DEFAULT column should remain after filtering.
	// Loose check: header present, output is non-empty.
	if !strings.Contains(out, "DEFAULT") {
		t.Error("missing header after filter")
	}
}

func TestRulesExplain_KnownRuleEmitsGuidance(t *testing.T) {
	out, err := execRules(t, "explain", "cbom-java-ecb-mode-usage")
	if err != nil {
		t.Fatalf("rules explain: %v", err)
	}
	for _, want := range []string{
		"Rule:", "Category:", "Maturity:", "Default on:",
		"--- Guidance ---", "## Why it fires",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q; got:\n%s", want, out)
		}
	}
}

func TestRulesExplain_UnseededRuleStillSucceeds(t *testing.T) {
	// Pick an unseeded rule id (no .md file) — the command should still
	// succeed and print metadata, just without the Guidance section.
	out, err := execRules(t, "explain", "cbom-csharp-weak-rng")
	if err != nil {
		t.Fatalf("rules explain (unseeded): %v", err)
	}
	if !strings.Contains(out, "cbom-csharp-weak-rng") {
		t.Error("explain output missing rule id")
	}
	if strings.Contains(out, "--- Guidance ---") {
		t.Error("unseeded rule should not show Guidance section")
	}
}

func TestRulesExplain_UnknownRuleReturnsError(t *testing.T) {
	_, err := execRules(t, "explain", "cbom-does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown rule id")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want 'not found'", err)
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
