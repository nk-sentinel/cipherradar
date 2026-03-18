package output

import (
	"encoding/json"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
)

// SARIFWriter writes scan results as SARIF 2.1 JSON.
type SARIFWriter struct{}

// Format returns the name of this output format.
func (w *SARIFWriter) Format() string { return "sarif" }

// WriteScanResult writes the scan results to the given writer as SARIF 2.1 JSON.
func (w *SARIFWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	doc := ConvertToSARIF(result)
	encoder := json.NewEncoder(wr)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

// ConvertToSARIF converts a types.ScanResult to a SARIF 2.1 document.
func ConvertToSARIF(result *types.ScanResult) *SARIFDocument {
	// Build deduplicated rules and the index mapping.
	rules, ruleIndexMap := buildSARIFRules(result.Findings)

	// Build results from findings.
	results := make([]SARIFResult, 0, len(result.Findings))
	for i := range result.Findings {
		results = append(results, convertFindingToSARIFResult(&result.Findings[i], ruleIndexMap))
	}

	return &SARIFDocument{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "CipherRadar",
						Version:        cipherRadarVersion,
						InformationURI: "https://github.com/nk-sentinel/cipherradar",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// buildSARIFRules creates a deduplicated list of SARIF rules from findings and
// returns a mapping from ruleID to the rule's index in the slice.
func buildSARIFRules(findings []types.Finding) ([]SARIFRule, map[string]int) {
	ruleIndexMap := make(map[string]int)
	var rules []SARIFRule

	for i := range findings {
		f := &findings[i]
		if _, exists := ruleIndexMap[f.RuleID]; exists {
			continue
		}
		idx := len(rules)
		ruleIndexMap[f.RuleID] = idx

		rule := SARIFRule{
			ID:   f.RuleID,
			Name: f.Name,
			ShortDescription: &SARIFMessage{
				Text: f.Description,
			},
			DefaultConfig: &SARIFRuleConfig{
				Level: severityToSARIFLevel(f.Severity),
			},
		}
		rules = append(rules, rule)
	}

	return rules, ruleIndexMap
}

// convertFindingToSARIFResult maps a single Finding to a SARIFResult.
func convertFindingToSARIFResult(f *types.Finding, ruleIndexMap map[string]int) SARIFResult {
	result := SARIFResult{
		RuleID:    f.RuleID,
		RuleIndex: ruleIndexMap[f.RuleID],
		Level:     severityToSARIFLevel(f.Severity),
		Message: SARIFMessage{
			Text: f.Description,
		},
		Properties: map[string]interface{}{
			"assetType":     string(f.AssetType),
			"quantumStatus": string(f.Properties.QuantumStatus),
			"confidence":    string(f.Confidence),
			"pass":          f.Pass,
		},
	}

	loc := buildSARIFLocation(f)
	result.Locations = []SARIFLocation{loc}

	return result
}

// buildSARIFLocation creates a SARIFLocation from a Finding.
func buildSARIFLocation(f *types.Finding) SARIFLocation {
	loc := SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: f.Location.File,
			},
		},
	}

	fl := &f.Location
	if fl.StartLine > 0 || fl.StartCol > 0 || fl.EndLine > 0 || fl.EndCol > 0 {
		loc.PhysicalLocation.Region = &SARIFRegion{
			StartLine:   fl.StartLine,
			StartColumn: fl.StartCol,
			EndLine:     fl.EndLine,
			EndColumn:   fl.EndCol,
		}
	}

	return loc
}

// severityToSARIFLevel maps a CipherRadar severity to a SARIF level string.
func severityToSARIFLevel(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow, types.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}
