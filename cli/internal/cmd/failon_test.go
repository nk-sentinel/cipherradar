package cmd

import (
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func mkFinding(name string, sev types.Severity, file string, line int) types.Finding {
	return types.Finding{
		Name:     name,
		Severity: sev,
		Location: types.Location{File: file, StartLine: line},
	}
}

func TestCheckFailOn_NoOffenders_Nil(t *testing.T) {
	findings := []types.Finding{
		mkFinding("a", types.SeverityLow, "a.go", 1),
	}
	if err := checkFailOn(findings, "high"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCheckFailOn_InvalidThreshold_ExitConfig(t *testing.T) {
	err := checkFailOn(nil, "urgent")
	if err == nil {
		t.Fatal("expected error")
	}
	if ExitCode(err) != ExitConfig {
		t.Errorf("bad severity should map to ExitConfig (%d), got %d", ExitConfig, ExitCode(err))
	}
}

func TestCheckFailOn_AggregatesEveryOffender(t *testing.T) {
	// 7 offenders across 2 severity buckets; message must include count-by-
	// severity and the first 5 as examples, plus a "N more" tail.
	findings := []types.Finding{
		mkFinding("c1", types.SeverityCritical, "a.go", 1),
		mkFinding("c2", types.SeverityCritical, "b.go", 2),
		mkFinding("h1", types.SeverityHigh, "c.go", 3),
		mkFinding("h2", types.SeverityHigh, "d.go", 4),
		mkFinding("h3", types.SeverityHigh, "e.go", 5),
		mkFinding("h4", types.SeverityHigh, "f.go", 6),
		mkFinding("h5", types.SeverityHigh, "g.go", 7),
		mkFinding("skip-low", types.SeverityLow, "z.go", 99),
	}
	err := checkFailOn(findings, "high")
	if err == nil {
		t.Fatal("expected error")
	}
	if ExitCode(err) != ExitFindings {
		t.Errorf("code: got %d, want %d", ExitCode(err), ExitFindings)
	}
	msg := err.Error()
	// 7 offenders total (5 high + 2 critical); low should not be counted.
	if !strings.Contains(msg, "7 finding(s) at or above high") {
		t.Errorf("total count missing in msg: %s", msg)
	}
	if !strings.Contains(msg, "[critical: 2]") || !strings.Contains(msg, "[high: 5]") {
		t.Errorf("per-severity counts missing: %s", msg)
	}
	if !strings.Contains(msg, "... 2 more") {
		t.Errorf("truncation tail missing (expected '... 2 more'): %s", msg)
	}
	// "c1" must appear — we should not stop after the first offender.
	if !strings.Contains(msg, "c1") {
		t.Errorf("examples block missing first offender: %s", msg)
	}
}
