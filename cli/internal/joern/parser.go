package joern

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// joernOutput represents the top-level JSON output from a Joern query script.
type joernOutput struct {
	Findings []joernFinding `json:"findings"`
}

// joernFinding represents a single finding from Joern JSON output.
type joernFinding struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	Line     int       `json:"line"`
	EndLine  int       `json:"endLine"`
	Column   int       `json:"column"`
	EndCol   int       `json:"endColumn"`
	Code     string    `json:"code"`
	Severity string    `json:"severity"`
	Flow     []flowHop `json:"flow"`
}

// flowHop represents a single hop in a Joern taint flow.
type flowHop struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Code string `json:"code"`
}

// ParseResults parses Joern JSON output into CipherRadar findings.
// All returned findings have Pass = 3.
// The ruleID is derived from the query script name by the caller.
func ParseResults(jsonData []byte, ruleID string) ([]types.Finding, error) {
	if len(jsonData) == 0 {
		return nil, nil
	}

	var output joernOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		return nil, fmt.Errorf("invalid joern JSON: %w", err)
	}

	findings := make([]types.Finding, 0, len(output.Findings))
	for _, jf := range output.Findings {
		f := types.Finding{
			RuleID:     ruleID,
			Pass:       3,
			Name:       jf.Name,
			Description: buildDescription(jf),
			Severity:   mapSeverity(jf.Severity),
			Confidence: types.ConfidenceHigh, // Joern inter-procedural analysis = high confidence
			AssetType:  types.AssetRelatedCryptoMaterial,
			Location: types.Location{
				File:      jf.File,
				StartLine: jf.Line,
				StartCol:  jf.Column,
				EndLine:   jf.EndLine,
				EndCol:    jf.EndCol,
				Snippet:   jf.Code,
			},
		}

		// Derive asset type from the rule ID when possible.
		f.AssetType = inferAssetType(ruleID, jf.Name)

		findings = append(findings, f)
	}

	return findings, nil
}

// mapSeverity maps Joern severity strings to CipherRadar Severity.
func mapSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium", "warning":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	case "info":
		return types.SeverityInfo
	default:
		return types.SeverityMedium
	}
}

// inferAssetType infers the CBOM asset type from the rule ID and finding name.
// The finding name is checked first (higher specificity), then the rule ID is
// consulted as a fallback. Protocol and certificate keywords take precedence
// over key/secret keywords to avoid false classification when a rule ID like
// "joern-crypto-key-flow" happens to contain "key".
func inferAssetType(ruleID string, name string) types.AssetType {
	nameLower := strings.ToLower(name)

	// Check the finding name first (most specific signal).
	switch {
	case strings.Contains(nameLower, "tls") || strings.Contains(nameLower, "ssl") ||
		strings.Contains(nameLower, "protocol"):
		return types.AssetProtocol
	case strings.Contains(nameLower, "cert"):
		return types.AssetCertificate
	case strings.Contains(nameLower, "key") || strings.Contains(nameLower, "secret") ||
		strings.Contains(nameLower, "iv") || strings.Contains(nameLower, "nonce"):
		return types.AssetRelatedCryptoMaterial
	}

	// Fall back to rule ID for classification.
	ruleIDLower := strings.ToLower(ruleID)
	switch {
	case strings.Contains(ruleIDLower, "tls") || strings.Contains(ruleIDLower, "ssl") ||
		strings.Contains(ruleIDLower, "protocol"):
		return types.AssetProtocol
	case strings.Contains(ruleIDLower, "cert"):
		return types.AssetCertificate
	case strings.Contains(ruleIDLower, "key") || strings.Contains(ruleIDLower, "secret") ||
		strings.Contains(ruleIDLower, "iv") || strings.Contains(ruleIDLower, "nonce"):
		return types.AssetRelatedCryptoMaterial
	default:
		return types.AssetAlgorithm
	}
}

// buildDescription creates a human-readable description from a Joern finding,
// including taint flow information when available.
func buildDescription(jf joernFinding) string {
	desc := jf.Name
	if len(jf.Flow) > 0 {
		hops := make([]string, 0, len(jf.Flow))
		for _, hop := range jf.Flow {
			hops = append(hops, fmt.Sprintf("%s:%d", hop.File, hop.Line))
		}
		desc += " [flow: " + strings.Join(hops, " -> ") + "]"
	}
	return desc
}
