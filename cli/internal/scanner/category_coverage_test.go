package scanner_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/rulefilter"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// TestAllScannerFindings_HaveCategory walks every per-language testdata
// fixture directory, runs the full default scanner registry against each,
// and asserts that every emitted Finding has a non-empty Category.
//
// Findings without Category get defaulted to CategorySecurity by the
// rulefilter layer, which silently drops them from --only-inventory output
// (the original Bug 4). This guard prevents future AST scanner additions
// from regressing the Pass-1 categorization fix.
func TestAllScannerFindings_HaveCategory(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("can't locate test file")
	}
	cliRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	testdataRoot := filepath.Join(cliRoot, "testdata")
	if _, err := os.Stat(testdataRoot); err != nil {
		t.Skipf("testdata dir not available: %v", err)
	}

	registry := scannerinit.DefaultRegistry()

	result, err := scanner.ScanDir(testdataRoot, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Skip("no findings produced from testdata — covered by per-scanner tests")
	}

	missing := map[string]int{}
	for _, f := range result.Findings {
		if f.Category == "" {
			key := f.RuleID
			if key == "" {
				key = f.Name
			}
			missing[key]++
		}
	}
	if len(missing) > 0 {
		for ruleID, count := range missing {
			t.Errorf("rule %q emitted %d findings without Category (would be dropped by --only-inventory)", ruleID, count)
		}
	}

	expected := map[types.Category]bool{
		types.CategoryInventory: true,
		types.CategorySecurity:  true,
	}
	for _, f := range result.Findings {
		if f.Category != "" && !expected[f.Category] {
			t.Errorf("rule %q has unexpected Category %q (expected inventory or security)", f.RuleID, f.Category)
		}
	}

	t.Logf("scanned %d findings across testdata; all have valid Category", len(result.Findings))
}

// TestPass1Findings_SurviveDefaultRulefilter is the end-to-end guard for Bug 4.
// It runs Pass 1 across every testdata fixture, then applies the same default
// rulefilter the scan CLI uses, and asserts that findings are not silently
// dropped at the default_enabled / category gates. Without this guard,
// regressions in AnnotateFindings (forgetting DefaultEnabled or NoiseRisk
// alongside Maturity) would compile and pass the per-scanner tests but
// produce a fully-empty scan in the CLI.
func TestPass1Findings_SurviveDefaultRulefilter(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("can't locate test file")
	}
	cliRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	testdataRoot := filepath.Join(cliRoot, "testdata")
	if _, err := os.Stat(testdataRoot); err != nil {
		t.Skipf("testdata dir not available: %v", err)
	}

	registry := scannerinit.DefaultRegistry()
	result, err := scanner.ScanDir(testdataRoot, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Skip("no findings produced from testdata — covered by per-scanner tests")
	}

	// Default scan filter — no category restriction, no rule allowlist.
	kept, stats := rulefilter.Apply(result.Findings, rulefilter.Options{})
	if len(kept) == 0 {
		t.Fatalf("rulefilter dropped ALL %d Pass-1 findings (stats=%+v) — "+
			"AnnotateFindings likely set Maturity without DefaultEnabled, "+
			"causing normalizeLifecycle to skip permissive defaults (Bug 4 regression)",
			stats.Input, stats)
	}
	// The default filter intentionally drops the noise-gated entropy rules
	// (off by default; see scanner.noiseGatedOffByDefault). Every OTHER Pass-1
	// rule must still survive the default_enabled gate — that is the Bug 4
	// regression this test guards.
	noiseGated := map[string]bool{
		"cbom-regex-hex-key":    true,
		"cbom-regex-base64-key": true,
	}
	allByRule := map[string]int{}
	for _, f := range result.Findings {
		allByRule[f.RuleID]++
	}
	keptByRule := map[string]int{}
	for _, f := range kept {
		keptByRule[f.RuleID]++
	}
	for rule, emitted := range allByRule {
		if noiseGated[rule] {
			if keptByRule[rule] != 0 {
				t.Errorf("noise-gated rule %s should be OFF by default, but %d survived", rule, keptByRule[rule])
			}
			continue
		}
		if keptByRule[rule] != emitted {
			t.Errorf("rule %s: %d emitted but only %d survived the default filter — "+
				"non-noise Pass-1 rules must not be dropped (Bug 4 regression)",
				rule, emitted, keptByRule[rule])
		}
	}

	// --include-noisy must bring the noise-gated rules back in full.
	noisyKept, _ := rulefilter.Apply(result.Findings, rulefilter.Options{IncludeNoisy: true})
	noisyByRule := map[string]int{}
	for _, f := range noisyKept {
		noisyByRule[f.RuleID]++
	}
	for rule := range noiseGated {
		if allByRule[rule] > 0 && noisyByRule[rule] != allByRule[rule] {
			t.Errorf("--include-noisy should re-enable %s: emitted %d, kept %d",
				rule, allByRule[rule], noisyByRule[rule])
		}
	}

	// --only-inventory must also produce a non-empty subset on Pass 1.
	invKept, invStats := rulefilter.Apply(result.Findings, rulefilter.Options{
		Categories: []types.Category{types.CategoryInventory},
	})
	if len(invKept) == 0 {
		t.Errorf("--only-inventory returned 0 findings on Pass 1 (stats=%+v) — "+
			"AnnotateFindings classification produced no inventory rules", invStats)
	}

	// --only-security must also produce a non-empty subset on Pass 1.
	secKept, secStats := rulefilter.Apply(result.Findings, rulefilter.Options{
		Categories: []types.Category{types.CategorySecurity},
	})
	if len(secKept) == 0 {
		t.Errorf("--only-security returned 0 findings on Pass 1 (stats=%+v) — "+
			"AnnotateFindings classification produced no security rules", secStats)
	}

	t.Logf("Pass 1: %d findings; default-filter kept %d, inventory=%d, security=%d",
		stats.Input, len(kept), len(invKept), len(secKept))
}
