package opengrep

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// opengrepOutput represents the top-level JSON output from OpenGrep/Semgrep.
type opengrepOutput struct {
	Results []opengrepResult `json:"results"`
	Errors  []opengrepError  `json:"errors"`
}

// opengrepResult represents a single result from OpenGrep JSON output.
type opengrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   opengrepPos     `json:"start"`
	End     opengrepPos     `json:"end"`
	Extra   opengrepExtra   `json:"extra"`
}

// opengrepPos represents a position in a file.
type opengrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

// opengrepExtra holds the metadata for an OpenGrep result.
type opengrepExtra struct {
	Message  string           `json:"message"`
	Severity string           `json:"severity"`
	Metadata opengrepMetadata `json:"metadata"`
	Lines    string           `json:"lines"`
}

// opengrepMetadata holds CBOM-specific metadata from rule annotations.
type opengrepMetadata struct {
	CbomAssetType   string `json:"cbom-asset-type"`
	Confidence      string `json:"confidence"`
	QuantumRelevant bool   `json:"quantum-relevant"`
}

// opengrepError represents an error reported by OpenGrep.
type opengrepError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

// ParseResults parses OpenGrep JSON output into CipherRadar findings.
// All returned findings have Pass = 2.
func ParseResults(jsonData []byte) ([]types.Finding, error) {
	if len(jsonData) == 0 {
		return nil, nil
	}

	var output opengrepOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		return nil, fmt.Errorf("invalid opengrep JSON: %w", err)
	}

	findings := make([]types.Finding, 0, len(output.Results))
	for _, r := range output.Results {
		f := types.Finding{
			RuleID:     r.CheckID,
			Pass:       2,
			Description: r.Extra.Message,
			Severity:   mapSeverity(r.Extra.Severity),
			Confidence: mapConfidence(r.Extra.Metadata.Confidence),
			AssetType:  mapAssetType(r.Extra.Metadata.CbomAssetType),
			Location: types.Location{
				File:      r.Path,
				StartLine: r.Start.Line,
				StartCol:  r.Start.Col,
				EndLine:   r.End.Line,
				EndCol:    r.End.Col,
				Snippet:   r.Extra.Lines,
			},
		}

		// Derive a name from the check_id if possible.
		f.Name = deriveNameFromCheckID(r.CheckID)

		findings = append(findings, f)
	}

	return findings, nil
}

// mapSeverity maps OpenGrep severity strings to CipherRadar Severity.
func mapSeverity(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return types.SeverityHigh
	case "WARNING":
		return types.SeverityMedium
	case "INFO":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// mapConfidence maps OpenGrep confidence strings to CipherRadar Confidence.
func mapConfidence(s string) types.Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return types.ConfidenceHigh
	case "medium":
		return types.ConfidenceMedium
	case "low":
		return types.ConfidenceLow
	default:
		return types.ConfidenceMedium
	}
}

// mapAssetType maps OpenGrep cbom-asset-type metadata to CipherRadar AssetType.
func mapAssetType(s string) types.AssetType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "algorithm":
		return types.AssetAlgorithm
	case "protocol":
		return types.AssetProtocol
	case "certificate":
		return types.AssetCertificate
	case "related-crypto-material":
		return types.AssetRelatedCryptoMaterial
	default:
		if s != "" {
			return types.AssetType(s)
		}
		return types.AssetAlgorithm
	}
}

// deriveNameFromCheckID attempts to extract a human-readable name from the check_id.
// For example, "cbom-python-hardcoded-key" becomes "hardcoded-key".
func deriveNameFromCheckID(checkID string) string {
	// Strip common prefixes.
	name := checkID
	for _, prefix := range []string{"cbom-python-", "cbom-java-", "cbom-javascript-", "cbom-js-", "cbom-"} {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			break
		}
	}
	return name
}
