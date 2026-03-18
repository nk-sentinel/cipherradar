package types

// PolicyResult represents the outcome of evaluating a single policy rule.
type PolicyResult string

const (
	// PolicyPass indicates the finding passes the policy rule.
	PolicyPass PolicyResult = "pass"
	// PolicyFail indicates the finding violates the policy rule.
	PolicyFail PolicyResult = "fail"
	// PolicyWarn indicates the finding triggers a policy warning.
	PolicyWarn PolicyResult = "warn"
)

// PolicyViolation represents a single policy rule violation or warning.
type PolicyViolation struct {
	// RuleID is the identifier of the policy rule that was evaluated.
	RuleID string `json:"rule_id"`
	// Description explains why the policy rule was triggered.
	Description string `json:"description"`
	// Finding is the cryptographic finding that triggered the violation.
	Finding Finding `json:"finding"`
	// Result is the outcome of the policy evaluation (pass, fail, or warn).
	Result PolicyResult `json:"result"`
	// Severity indicates the risk level of the violation.
	Severity Severity `json:"severity"`
}

// PolicyReport holds the result of evaluating a CBOM against a policy.
type PolicyReport struct {
	// Violations lists all policy violations and warnings found.
	Violations []PolicyViolation `json:"violations"`
	// Summary provides aggregate counts by result type.
	Summary PolicySummary `json:"summary"`
}

// PolicySummary provides aggregate counts of policy evaluation results.
type PolicySummary struct {
	// TotalFindings is the total number of findings evaluated.
	TotalFindings int `json:"total_findings"`
	// PassCount is the number of findings that passed all policy rules.
	PassCount int `json:"pass_count"`
	// FailCount is the number of findings that failed a policy rule.
	FailCount int `json:"fail_count"`
	// WarnCount is the number of findings that triggered a policy warning.
	WarnCount int `json:"warn_count"`
}
