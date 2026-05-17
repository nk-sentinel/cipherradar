package rulefilter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// mk builds a test finding with the given lifecycle metadata. Keeping this
// helper short so test tables stay readable.
func mk(ruleID string, cat types.Category, mat types.Maturity, def bool, noise types.NoiseRisk) types.Finding {
	return types.Finding{
		RuleID:         ruleID,
		Name:           ruleID,
		Category:       cat,
		Maturity:       mat,
		DefaultEnabled: def,
		NoiseRisk:      noise,
	}
}

// baseline mimics the real rule mix after Phase B:
//   - inv-stable       : inventory, stable, enabled, low — always kept
//   - sec-stable       : security,  stable, enabled, low — kept by default
//   - sec-experimental : security,  experimental, disabled, high — opt-in only
//   - sec-noisy-stable : security,  stable, disabled, high — opt-in only
//   - sec-deprecated   : security,  deprecated, enabled, low — kept + warn
func baseline() []types.Finding {
	return []types.Finding{
		mk("inv-stable", types.CategoryInventory, types.MaturityStable, true, types.NoiseRiskLow),
		mk("sec-stable", types.CategorySecurity, types.MaturityStable, true, types.NoiseRiskLow),
		mk("sec-experimental", types.CategorySecurity, types.MaturityExperimental, false, types.NoiseRiskHigh),
		mk("sec-noisy-stable", types.CategorySecurity, types.MaturityStable, false, types.NoiseRiskHigh),
		mk("sec-deprecated", types.CategorySecurity, types.MaturityDeprecated, true, types.NoiseRiskLow),
	}
}

func keptIDs(findings []types.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func TestApply_DefaultScanKeepsStableDefaultRules(t *testing.T) {
	kept, stats := Apply(baseline(), Options{})
	got := keptIDs(kept)
	want := []string{"inv-stable", "sec-stable", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("default scan kept %v, want %v", got, want)
	}
	if stats.Input != 5 || stats.Kept != 3 {
		t.Errorf("stats = %+v, want Input=5 Kept=3", stats)
	}
	// Deprecated rule should be tracked for the warning.
	if len(stats.DeprecatedRulesSeen) != 1 || stats.DeprecatedRulesSeen[0] != "sec-deprecated" {
		t.Errorf("DeprecatedRulesSeen = %v, want [sec-deprecated]", stats.DeprecatedRulesSeen)
	}
}

func TestApply_OnlyInventory(t *testing.T) {
	kept, _ := Apply(baseline(), Options{
		Categories: []types.Category{types.CategoryInventory},
	})
	got := keptIDs(kept)
	want := []string{"inv-stable"}
	if !equal(got, want) {
		t.Errorf("--only-inventory kept %v, want %v", got, want)
	}
}

func TestApply_OnlySecurity(t *testing.T) {
	kept, _ := Apply(baseline(), Options{
		Categories: []types.Category{types.CategorySecurity},
	})
	got := keptIDs(kept)
	// inv-stable excluded; sec-experimental and sec-noisy-stable still gated by defaults.
	want := []string{"sec-stable", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("--only-security kept %v, want %v", got, want)
	}
}

func TestApply_IncludeExperimental(t *testing.T) {
	kept, _ := Apply(baseline(), Options{IncludeExperimental: true})
	got := keptIDs(kept)
	// Experimental rule still has default_enabled:false + noise_risk:high, so
	// it also needs IncludeNoisy to actually come through. Verified separately.
	// With only --include-experimental, the maturity gate passes but the
	// default_enabled + noise gate still blocks it.
	want := []string{"inv-stable", "sec-stable", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("--include-experimental alone kept %v, want %v", got, want)
	}
}

func TestApply_IncludeExperimentalPlusNoisy(t *testing.T) {
	kept, _ := Apply(baseline(), Options{
		IncludeExperimental: true,
		IncludeNoisy:        true,
	})
	got := keptIDs(kept)
	want := []string{"inv-stable", "sec-stable", "sec-experimental", "sec-noisy-stable", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("--include-experimental --include-noisy kept %v, want %v", got, want)
	}
}

func TestApply_IncludeRuleOneOff(t *testing.T) {
	kept, _ := Apply(baseline(), Options{
		IncludeRules: []string{"sec-experimental"},
	})
	got := keptIDs(kept)
	// One-off per-rule opt-in should bring sec-experimental back WITHOUT
	// also enabling sec-noisy-stable.
	want := []string{"inv-stable", "sec-stable", "sec-experimental", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("--include-rule sec-experimental kept %v, want %v", got, want)
	}
}

func TestApply_DisableRuleWins(t *testing.T) {
	// --disable-rule subtracts last — even an experimental rule brought in
	// by --include-experimental + --include-noisy should go.
	kept, stats := Apply(baseline(), Options{
		IncludeExperimental: true,
		IncludeNoisy:        true,
		DisabledRules:       []string{"sec-experimental", "inv-stable"},
	})
	got := keptIDs(kept)
	want := []string{"sec-stable", "sec-noisy-stable", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("--disable-rule kept %v, want %v", got, want)
	}
	if stats.DroppedByDisable != 2 {
		t.Errorf("DroppedByDisable = %d, want 2", stats.DroppedByDisable)
	}
}

func TestApply_RulesAllowlistOverridesDefaults(t *testing.T) {
	// --rules acts as an explicit whitelist — bypasses default_enabled gate.
	kept, stats := Apply(baseline(), Options{
		Rules: []string{"sec-experimental"},
	})
	got := keptIDs(kept)
	want := []string{"sec-experimental"}
	if !equal(got, want) {
		t.Errorf("--rules allowlist kept %v, want %v", got, want)
	}
	if stats.DroppedByRulesAllowlist != 4 {
		t.Errorf("DroppedByRulesAllowlist = %d, want 4", stats.DroppedByRulesAllowlist)
	}
}

func TestApply_RulesAllowlistPlusCategoryStacks(t *testing.T) {
	// Combining --rules with --only-inventory: whitelist first, then category.
	// sec-experimental is in the allowlist but is security, so category cuts it.
	kept, _ := Apply(baseline(), Options{
		Rules:      []string{"sec-experimental", "inv-stable"},
		Categories: []types.Category{types.CategoryInventory},
	})
	got := keptIDs(kept)
	want := []string{"inv-stable"}
	if !equal(got, want) {
		t.Errorf("--rules + --only-inventory kept %v, want %v", got, want)
	}
}

func TestApply_EmptyInput(t *testing.T) {
	kept, stats := Apply(nil, Options{})
	if len(kept) != 0 {
		t.Errorf("expected no findings, got %d", len(kept))
	}
	if stats.Input != 0 {
		t.Errorf("stats.Input = %d, want 0", stats.Input)
	}
}

func TestApply_PreservesFindingOrder(t *testing.T) {
	kept, _ := Apply(baseline(), Options{
		IncludeExperimental: true,
		IncludeNoisy:        true,
	})
	ids := keptIDs(kept)
	// Input order was inv, sec-stable, sec-experimental, sec-noisy, sec-deprecated.
	// All kept → same order.
	want := []string{"inv-stable", "sec-stable", "sec-experimental", "sec-noisy-stable", "sec-deprecated"}
	if !equal(ids, want) {
		t.Errorf("order not preserved: %v vs %v", ids, want)
	}
}

func TestApply_DeprecatedRuleAlwaysRunsUntilRemoved(t *testing.T) {
	// Even without --include-deprecated, deprecated rules still produce
	// findings (ADR-034: 2 minor releases of warning). Only the warning is
	// silenced by the flag.
	kept, _ := Apply(baseline(), Options{IncludeDeprecated: true})
	got := keptIDs(kept)
	want := []string{"inv-stable", "sec-stable", "sec-deprecated"}
	if !equal(got, want) {
		t.Errorf("--include-deprecated kept %v, want %v", got, want)
	}
}

func TestWarnDeprecated_EmptyWhenNoneSeen(t *testing.T) {
	var buf bytes.Buffer
	WarnDeprecated(&buf, Stats{}, false)
	if buf.Len() != 0 {
		t.Errorf("expected silent when no deprecated rules; got %q", buf.String())
	}
}

func TestWarnDeprecated_SilentWhenIncludeDeprecated(t *testing.T) {
	var buf bytes.Buffer
	WarnDeprecated(&buf, Stats{DeprecatedRulesSeen: []string{"foo"}}, true)
	if buf.Len() != 0 {
		t.Errorf("expected silent with --include-deprecated; got %q", buf.String())
	}
}

func TestWarnDeprecated_EmitsAggregatedWarning(t *testing.T) {
	var buf bytes.Buffer
	WarnDeprecated(&buf, Stats{DeprecatedRulesSeen: []string{"rule-b", "rule-a"}}, false)
	out := buf.String()
	if !strings.Contains(out, "deprecated rule(s) fired") {
		t.Errorf("warning text missing preamble; got %q", out)
	}
	// Both IDs present.
	if !strings.Contains(out, "rule-a") || !strings.Contains(out, "rule-b") {
		t.Errorf("warning missing rule ids; got %q", out)
	}
	// ADR-034 reference present.
	if !strings.Contains(out, "ADR-034") {
		t.Errorf("warning missing ADR reference; got %q", out)
	}
}

func TestApply_PreLifecycleFindingsKeptByDefault(t *testing.T) {
	// Pass 1 (tree-sitter) scanners don't yet emit lifecycle metadata.
	// Findings with empty Maturity should NOT be silently dropped — they
	// must flow through a default scan unchanged.
	preLifecycle := types.Finding{RuleID: "cbom-python-treesitter-aes", Name: "aes"}
	kept, stats := Apply([]types.Finding{preLifecycle}, Options{})
	if len(kept) != 1 {
		t.Fatalf("expected pre-lifecycle finding kept; got %d", len(kept))
	}
	// Original finding should be returned unmodified (empty Maturity still).
	if kept[0].Maturity != "" {
		t.Errorf("filter must not mutate finding; got Maturity=%q", kept[0].Maturity)
	}
	if stats.Kept != 1 {
		t.Errorf("stats.Kept = %d, want 1", stats.Kept)
	}
}

func TestApply_PreLifecycleFindingFiltersAsSecurity(t *testing.T) {
	// Pre-lifecycle findings normalize to Category=security. --only-inventory
	// should drop them; --only-security should keep them.
	preLifecycle := types.Finding{RuleID: "cbom-python-treesitter-aes", Name: "aes"}

	keptInv, _ := Apply([]types.Finding{preLifecycle}, Options{
		Categories: []types.Category{types.CategoryInventory},
	})
	if len(keptInv) != 0 {
		t.Errorf("--only-inventory should drop pre-lifecycle finding; kept %d", len(keptInv))
	}

	keptSec, _ := Apply([]types.Finding{preLifecycle}, Options{
		Categories: []types.Category{types.CategorySecurity},
	})
	if len(keptSec) != 1 {
		t.Errorf("--only-security should keep pre-lifecycle finding; kept %d", len(keptSec))
	}
}

// equal compares two string slices element-wise (order-sensitive).
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
