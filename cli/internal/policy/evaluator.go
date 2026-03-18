package policy

import (
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// severityRank maps severity strings to numeric ranks for comparison.
// Higher rank means more severe.
var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Evaluate checks all findings against the policy rules and returns a PolicyReport.
func Evaluate(findings []types.Finding, config *PolicyConfig) *types.PolicyReport {
	report := &types.PolicyReport{
		Violations: []types.PolicyViolation{},
		Summary: types.PolicySummary{
			TotalFindings: len(findings),
		},
	}

	for i := range config.Rules {
		rule := &config.Rules[i]
		matched := false

		for j := range findings {
			finding := &findings[j]
			if matchesCondition(finding, &rule.Condition) {
				matched = true
				result := policyResultFromAction(rule.Action)
				violation := types.PolicyViolation{
					RuleID:      rule.ID,
					Description: violationDescription(rule, finding),
					Finding:     *finding,
					Result:      result,
					Severity:    types.Severity(rule.Severity),
				}
				report.Violations = append(report.Violations, violation)

				switch result {
				case types.PolicyFail:
					report.Summary.FailCount++
				case types.PolicyWarn:
					report.Summary.WarnCount++
				}
			}
		}

		if !matched {
			// Rule passed — no findings violated it.
			report.Summary.PassCount++
		}
	}

	return report
}

// matchesCondition checks if a finding matches the rule condition.
func matchesCondition(f *types.Finding, cond *Condition) bool {
	// Check deny_algorithms
	if len(cond.DenyAlgorithms) > 0 {
		algoFamily := strings.ToLower(f.Properties.AlgorithmFamily)
		if algoFamily != "" && containsLower(cond.DenyAlgorithms, algoFamily) {
			return true
		}
	}

	// Check deny_modes
	if len(cond.DenyModes) > 0 {
		mode := strings.ToLower(f.Properties.Mode)
		if mode != "" && containsLower(cond.DenyModes, mode) {
			return true
		}
	}

	// Check min_key_size + algorithm
	if cond.MinKeySize > 0 && cond.Algorithm != "" {
		algoFamily := strings.ToLower(f.Properties.AlgorithmFamily)
		if algoFamily == strings.ToLower(cond.Algorithm) && f.Properties.KeySize > 0 && f.Properties.KeySize < cond.MinKeySize {
			return true
		}
	}

	// Check deny_tls_versions
	if len(cond.DenyTLSVersions) > 0 {
		version := f.Properties.ProtocolVersion
		if version != "" && contains(cond.DenyTLSVersions, version) {
			return true
		}
	}

	// Check deny_quantum_status
	if len(cond.DenyQuantumStatus) > 0 {
		qs := string(f.Properties.QuantumStatus)
		if qs != "" && containsLower(cond.DenyQuantumStatus, strings.ToLower(qs)) {
			return true
		}
	}

	// Check min_severity
	if cond.MinSeverity != "" {
		findingSev := strings.ToLower(string(f.Severity))
		threshold := strings.ToLower(cond.MinSeverity)
		findingRank, fOk := severityRank[findingSev]
		thresholdRank, tOk := severityRank[threshold]
		if fOk && tOk && findingRank >= thresholdRank {
			return true
		}
	}

	return false
}

// policyResultFromAction converts a rule action to a PolicyResult.
func policyResultFromAction(action string) types.PolicyResult {
	switch strings.ToLower(action) {
	case "fail":
		return types.PolicyFail
	case "warn":
		return types.PolicyWarn
	default:
		return types.PolicyFail
	}
}

// violationDescription creates a human-readable description of the violation.
func violationDescription(rule *Rule, f *types.Finding) string {
	loc := ""
	if f.Location.File != "" {
		loc = f.Location.File
		if f.Location.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.StartLine)
		}
	}

	if loc != "" {
		return fmt.Sprintf("%s found in %s", f.Name, loc)
	}
	return fmt.Sprintf("%s detected", f.Name)
}

// containsLower checks if the list contains the target (case-insensitive comparison).
func containsLower(list []string, target string) bool {
	t := strings.ToLower(target)
	for _, item := range list {
		if strings.ToLower(item) == t {
			return true
		}
	}
	return false
}

// contains checks if the list contains the target (exact match).
func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
