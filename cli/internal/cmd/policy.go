package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/policy"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management commands",
}

var policyCheckCmd = &cobra.Command{
	Use:   "check <cbom.json>",
	Short: "Check a CBOM against a policy file",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyCheck,
}

func init() {
	policyCheckCmd.Flags().StringP("policy", "p", "policy.cradar.yml", "path to policy file")
	policyCheckCmd.Flags().String("fail-on", "critical", "minimum severity that causes a non-zero exit")

	policyCmd.AddCommand(policyCheckCmd)
	rootCmd.AddCommand(policyCmd)
}

// severityRank maps severity strings to numeric ranks for fail-on comparison.
var cmdSeverityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func runPolicyCheck(cmd *cobra.Command, args []string) error {
	cbomPath := args[0]
	policyPath, _ := cmd.Flags().GetString("policy")
	failOn, _ := cmd.Flags().GetString("fail-on")

	// Load the CBOM JSON file.
	findings, err := policy.LoadCBOM(cbomPath)
	if err != nil {
		return fmt.Errorf("loading CBOM: %w", err)
	}

	// Load the policy YAML file.
	config, err := policy.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	// Run the evaluator.
	report := policy.Evaluate(findings, config)

	// Apply --fail-on override: reclassify violations based on severity threshold.
	failOnLower := strings.ToLower(failOn)
	failOnRank, validFailOn := cmdSeverityRank[failOnLower]
	if !validFailOn {
		failOnRank = cmdSeverityRank["critical"]
	}

	// Reclassify: violations at or above --fail-on become FAIL; others become WARN.
	adjustedFailCount := 0
	adjustedWarnCount := 0
	for i := range report.Violations {
		v := &report.Violations[i]
		vRank, ok := cmdSeverityRank[strings.ToLower(string(v.Severity))]
		if !ok {
			vRank = 0
		}
		if vRank >= failOnRank {
			v.Result = types.PolicyFail
			adjustedFailCount++
		} else {
			v.Result = types.PolicyWarn
			adjustedWarnCount++
		}
	}

	// Recalculate summary based on adjusted results.
	totalRules := len(config.Rules)
	report.Summary.FailCount = adjustedFailCount
	report.Summary.WarnCount = adjustedWarnCount
	// PassCount = total rules minus rules that had any violation.
	rulesWithViolations := countDistinctRulesWithViolations(report)
	report.Summary.PassCount = totalRules - rulesWithViolations

	// Print results.
	printPolicyReport(report, config, cbomPath, policyPath, totalRules)

	// Exit-code contract (ADR-036): 1 on any fail, 2 on warn-only, 0 on pass.
	// Return typed errors so deferred cleanup in Execute runs and main.go
	// maps the code.
	if adjustedFailCount > 0 {
		return NewExitError(ExitFindings,
			fmt.Sprintf("policy check failed: %d violation(s) at or above %s", adjustedFailCount, failOn))
	}
	if adjustedWarnCount > 0 {
		return NewExitError(ExitWarnings,
			fmt.Sprintf("policy check warnings: %d violation(s) below %s", adjustedWarnCount, failOn))
	}

	return nil
}

// countDistinctRulesWithViolations counts how many distinct rules have violations.
func countDistinctRulesWithViolations(report *types.PolicyReport) int {
	seen := make(map[string]struct{})
	for _, v := range report.Violations {
		seen[v.RuleID] = struct{}{}
	}
	return len(seen)
}

func printPolicyReport(report *types.PolicyReport, config *policy.PolicyConfig, cbomPath, policyPath string, totalRules int) {
	fmt.Println("CipherRadar Policy Check")
	fmt.Println("========================")
	fmt.Printf("Policy:   %s\n", filepath.Base(policyPath))
	fmt.Printf("CBOM:     %s\n", filepath.Base(cbomPath))
	fmt.Printf("Rules:    %d\n", totalRules)
	fmt.Println()
	fmt.Println("Results:")

	// Print violations (FAIL and WARN).
	for _, v := range report.Violations {
		status := strings.ToUpper(string(v.Result))
		fmt.Printf("  %-6s %-25s %s\n", status, v.RuleID, v.Description)
	}

	// Print rules that passed (no violations).
	violatedRules := make(map[string]struct{})
	for _, v := range report.Violations {
		violatedRules[v.RuleID] = struct{}{}
	}
	for _, rule := range config.Rules {
		if _, violated := violatedRules[rule.ID]; !violated {
			fmt.Printf("  %-6s %-25s %s\n", "PASS", rule.ID, passDescription(&rule))
		}
	}

	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("  Rules evaluated: %d\n", totalRules)
	fmt.Printf("  PASS: %d\n", report.Summary.PassCount)
	fmt.Printf("  FAIL: %d\n", report.Summary.FailCount)
	fmt.Printf("  WARN: %d\n", report.Summary.WarnCount)
	fmt.Println()

	if report.Summary.FailCount > 0 {
		fmt.Println("Status: FAIL (exit code 1)")
	} else if report.Summary.WarnCount > 0 {
		fmt.Println("Status: WARN (exit code 2)")
	} else {
		fmt.Println("Status: PASS (exit code 0)")
	}
}

// passDescription generates a human-readable description for a passed rule.
func passDescription(rule *policy.Rule) string {
	cond := &rule.Condition

	if len(cond.DenyAlgorithms) > 0 {
		return fmt.Sprintf("No denied algorithms (%s) found", strings.Join(cond.DenyAlgorithms, ", "))
	}
	if len(cond.DenyModes) > 0 {
		return fmt.Sprintf("No denied modes (%s) found", strings.Join(cond.DenyModes, ", "))
	}
	if cond.MinKeySize > 0 && cond.Algorithm != "" {
		return fmt.Sprintf("All %s keys >= %d bits", strings.ToUpper(cond.Algorithm), cond.MinKeySize)
	}
	if len(cond.DenyTLSVersions) > 0 {
		return fmt.Sprintf("No denied TLS versions (%s) found", strings.Join(cond.DenyTLSVersions, ", "))
	}
	if len(cond.DenyQuantumStatus) > 0 {
		return fmt.Sprintf("No %s assets found", strings.Join(cond.DenyQuantumStatus, ", "))
	}
	if cond.MinSeverity != "" {
		return fmt.Sprintf("No findings at or above %s severity", cond.MinSeverity)
	}

	return rule.Description
}
