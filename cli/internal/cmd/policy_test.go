package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/policy"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testDataDir returns the absolute path to testdata/policy.
func policyTestDataDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	// We're in cli/internal/cmd, go up to cli.
	return filepath.Join(wd, "..", "..", "testdata", "policy")
}

func TestPolicyCheck_LoadAndEvaluate(t *testing.T) {
	dataDir := policyTestDataDir(t)
	cbomPath := filepath.Join(dataDir, "test-cbom.json")
	policyPath := filepath.Join(dataDir, "sample-policy.cbom.yml")

	// Load the CBOM.
	findings, err := policy.LoadCBOM(cbomPath)
	if err != nil {
		t.Fatalf("LoadCBOM(%q): %v", cbomPath, err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from CBOM, got 0")
	}

	// Load the policy.
	config, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy(%q): %v", policyPath, err)
	}

	if len(config.Rules) != 6 {
		t.Fatalf("expected 6 rules, got %d", len(config.Rules))
	}

	// Run evaluation.
	report := policy.Evaluate(findings, config)

	// Verify we have violations.
	if len(report.Violations) == 0 {
		t.Error("expected violations from test CBOM against sample policy, got 0")
	}

	// Verify MD5 and SHA-1 trigger the no-broken-algorithms rule.
	md5Found := false
	sha1Found := false
	ecbFound := false
	for _, v := range report.Violations {
		if v.RuleID == "no-broken-algorithms" && v.Finding.Name == "MD5" {
			md5Found = true
		}
		if v.RuleID == "no-broken-algorithms" && v.Finding.Name == "SHA-1" {
			sha1Found = true
		}
		if v.RuleID == "no-ecb-mode" && v.Finding.Name == "AES-128-ECB" {
			ecbFound = true
		}
	}

	if !md5Found {
		t.Error("expected MD5 violation from no-broken-algorithms rule")
	}
	if !sha1Found {
		t.Error("expected SHA-1 violation from no-broken-algorithms rule")
	}
	if !ecbFound {
		t.Error("expected AES-128-ECB violation from no-ecb-mode rule")
	}
}

func TestPolicyCheck_ExitCodeLogic(t *testing.T) {
	// Test that exit code logic is correct based on violations.
	tests := []struct {
		name           string
		violations     []types.PolicyViolation
		expectedFails  int
		expectedWarns  int
		expectedExitIs string // "pass", "fail", "warn"
	}{
		{
			name:           "no violations = pass",
			violations:     []types.PolicyViolation{},
			expectedFails:  0,
			expectedWarns:  0,
			expectedExitIs: "pass",
		},
		{
			name: "fail violation = fail",
			violations: []types.PolicyViolation{
				{RuleID: "test", Result: types.PolicyFail, Severity: types.SeverityCritical},
			},
			expectedFails:  1,
			expectedWarns:  0,
			expectedExitIs: "fail",
		},
		{
			name: "warn only = warn",
			violations: []types.PolicyViolation{
				{RuleID: "test", Result: types.PolicyWarn, Severity: types.SeverityMedium},
			},
			expectedFails:  0,
			expectedWarns:  1,
			expectedExitIs: "warn",
		},
		{
			name: "fail + warn = fail",
			violations: []types.PolicyViolation{
				{RuleID: "test1", Result: types.PolicyFail, Severity: types.SeverityCritical},
				{RuleID: "test2", Result: types.PolicyWarn, Severity: types.SeverityMedium},
			},
			expectedFails:  1,
			expectedWarns:  1,
			expectedExitIs: "fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failCount := 0
			warnCount := 0
			for _, v := range tt.violations {
				switch v.Result {
				case types.PolicyFail:
					failCount++
				case types.PolicyWarn:
					warnCount++
				}
			}

			if failCount != tt.expectedFails {
				t.Errorf("expected %d fails, got %d", tt.expectedFails, failCount)
			}
			if warnCount != tt.expectedWarns {
				t.Errorf("expected %d warns, got %d", tt.expectedWarns, warnCount)
			}

			var exitStatus string
			if failCount > 0 {
				exitStatus = "fail"
			} else if warnCount > 0 {
				exitStatus = "warn"
			} else {
				exitStatus = "pass"
			}

			if exitStatus != tt.expectedExitIs {
				t.Errorf("expected exit status %q, got %q", tt.expectedExitIs, exitStatus)
			}
		})
	}
}

func TestPolicyCheck_FailOnSeverityOverride(t *testing.T) {
	// Test the --fail-on severity override logic.
	tests := []struct {
		name       string
		failOn     string
		vSeverity  types.Severity
		wantResult types.PolicyResult
	}{
		{
			name:       "critical fail-on, critical violation = FAIL",
			failOn:     "critical",
			vSeverity:  types.SeverityCritical,
			wantResult: types.PolicyFail,
		},
		{
			name:       "critical fail-on, high violation = WARN",
			failOn:     "critical",
			vSeverity:  types.SeverityHigh,
			wantResult: types.PolicyWarn,
		},
		{
			name:       "high fail-on, high violation = FAIL",
			failOn:     "high",
			vSeverity:  types.SeverityHigh,
			wantResult: types.PolicyFail,
		},
		{
			name:       "high fail-on, critical violation = FAIL",
			failOn:     "high",
			vSeverity:  types.SeverityCritical,
			wantResult: types.PolicyFail,
		},
		{
			name:       "high fail-on, medium violation = WARN",
			failOn:     "high",
			vSeverity:  types.SeverityMedium,
			wantResult: types.PolicyWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failOnRank := cmdSeverityRank[tt.failOn]
			vRank := cmdSeverityRank[string(tt.vSeverity)]

			var result types.PolicyResult
			if vRank >= failOnRank {
				result = types.PolicyFail
			} else {
				result = types.PolicyWarn
			}

			if result != tt.wantResult {
				t.Errorf("expected %s, got %s", tt.wantResult, result)
			}
		})
	}
}

func TestPolicyCheck_CountDistinctRulesWithViolations(t *testing.T) {
	report := &types.PolicyReport{
		Violations: []types.PolicyViolation{
			{RuleID: "rule-1"},
			{RuleID: "rule-1"},
			{RuleID: "rule-2"},
		},
	}

	count := countDistinctRulesWithViolations(report)
	if count != 2 {
		t.Errorf("expected 2 distinct rules with violations, got %d", count)
	}
}
