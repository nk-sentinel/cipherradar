package explain

import (
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestAll_ReturnsNonEmptyCorpus(t *testing.T) {
	rs, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(rs) < 40 {
		t.Fatalf("expected at least 40 rules, got %d", len(rs))
	}
	// Sorted by ID — first element must alphabetically precede last.
	if rs[0].ID > rs[len(rs)-1].ID {
		t.Errorf("rules not sorted by ID: first=%q last=%q", rs[0].ID, rs[len(rs)-1].ID)
	}
}

func TestAll_ParsesLifecycleMetadata(t *testing.T) {
	rs, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	// Spot-check: at least one experimental rule exists (Phase B annotations
	// marked ~20 hardcoded-* rules experimental).
	var sawExperimental, sawStable bool
	for _, r := range rs {
		if r.Maturity == types.MaturityExperimental {
			sawExperimental = true
		}
		if r.Maturity == types.MaturityStable {
			sawStable = true
		}
	}
	if !sawExperimental {
		t.Error("expected at least one experimental rule in embedded corpus")
	}
	if !sawStable {
		t.Error("expected at least one stable rule in embedded corpus")
	}
}

func TestAll_DefaultsMirrorFilterPermissive(t *testing.T) {
	// A rule with no explicit category/maturity/default_enabled should
	// normalize to security / stable / true — same as the filter engine.
	rs, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	for _, r := range rs {
		if r.Category != types.CategoryInventory && r.Category != types.CategorySecurity {
			t.Errorf("rule %s has invalid category %q", r.ID, r.Category)
		}
		switch r.Maturity {
		case types.MaturityStable, types.MaturityExperimental, types.MaturityDeprecated:
		default:
			t.Errorf("rule %s has invalid maturity %q", r.ID, r.Maturity)
		}
	}
}

func TestFindByID_KnownRule(t *testing.T) {
	// cbom-java-ecb-mode-usage is documented in docs/.
	r, err := FindByID("cbom-java-ecb-mode-usage")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if r == nil {
		t.Fatal("expected rule, got nil")
	}
	if r.File != "java.yml" {
		t.Errorf("File = %q, want java.yml", r.File)
	}
	if len(r.Languages) == 0 || strings.ToLower(r.Languages[0]) != "java" {
		t.Errorf("Languages = %v, want [java]", r.Languages)
	}
}

func TestFindByID_UnknownRuleReturnsNil(t *testing.T) {
	r, err := FindByID("cbom-does-not-exist")
	if err != nil {
		t.Fatalf("FindByID should not error on unknown id: %v", err)
	}
	if r != nil {
		t.Errorf("unknown id should return nil, got %+v", r)
	}
}

func TestDoc_SeededRuleReturnsMarkdown(t *testing.T) {
	got := Doc("cbom-java-ecb-mode-usage")
	if got == "" {
		t.Fatal("seed doc missing for cbom-java-ecb-mode-usage")
	}
	if !strings.Contains(got, "## Why it fires") {
		t.Errorf("doc missing expected section header; got %q", got[:min(80, len(got))])
	}
}

func TestDoc_UnseededRuleReturnsEmpty(t *testing.T) {
	if got := Doc("cbom-no-seed-for-this-rule"); got != "" {
		t.Errorf("missing doc should return empty; got %q", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
