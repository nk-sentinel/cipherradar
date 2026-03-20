package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// SonarQubeWriter writes scan results as SonarQube Generic Issue Import JSON.
// See: https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/
type SonarQubeWriter struct{}

// Format returns the format name.
func (w *SonarQubeWriter) Format() string { return "sonarqube-generic" }

// WriteScanResult converts findings to SonarQube Generic Issue format.
func (w *SonarQubeWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	doc := convertToSonarQube(result)
	encoder := json.NewEncoder(wr)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

// sonarqube types

type sqDocument struct {
	Rules  []sqRule  `json:"rules"`
	Issues []sqIssue `json:"issues"`
}

type sqRule struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Description        string     `json:"description,omitempty"`
	EngineID           string     `json:"engineId"`
	CleanCodeAttribute string     `json:"cleanCodeAttribute"`
	Impacts            []sqImpact `json:"impacts"`
}

type sqImpact struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

type sqIssue struct {
	RuleID          string            `json:"ruleId"`
	EngineID        string            `json:"engineId"`
	PrimaryLocation sqPrimaryLocation `json:"primaryLocation"`
	Severity        string            `json:"severity"`
	Type            string            `json:"type"`
	EffortMinutes   int               `json:"effortMinutes,omitempty"`
}

type sqPrimaryLocation struct {
	FilePath  string       `json:"filePath"`
	Message   string       `json:"message"`
	TextRange *sqTextRange `json:"textRange,omitempty"`
}

type sqTextRange struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

func convertToSonarQube(result *types.ScanResult) *sqDocument {
	ruleMap := make(map[string]sqRule)
	var issues []sqIssue

	for _, f := range result.Findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = fmt.Sprintf("cipherradar-%s", strings.ToLower(string(f.AssetType)))
		}

		// Build rule (deduplicated)
		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = sqRule{
				ID:                 ruleID,
				Name:               f.Name,
				Description:        f.Description,
				EngineID:           "cipherradar",
				CleanCodeAttribute: "TRUSTWORTHY",
				Impacts: []sqImpact{
					{SoftwareQuality: "SECURITY", Severity: mapSQImpactSeverity(f.Severity)},
				},
			}
		}

		// Build issue
		issue := sqIssue{
			RuleID:   ruleID,
			EngineID: "cipherradar",
			PrimaryLocation: sqPrimaryLocation{
				FilePath: f.Location.File,
				Message:  f.Description,
			},
			Severity:      mapSQSeverity(f.Severity),
			Type:          "VULNERABILITY",
			EffortMinutes: estimateEffort(f.Severity),
		}

		if f.Location.StartLine > 0 {
			issue.PrimaryLocation.TextRange = &sqTextRange{
				StartLine:   f.Location.StartLine,
				StartColumn: f.Location.StartCol,
				EndLine:     f.Location.EndLine,
				EndColumn:   f.Location.EndCol,
			}
		}

		issues = append(issues, issue)
	}

	// Collect rules
	rules := make([]sqRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	return &sqDocument{Rules: rules, Issues: issues}
}

func mapSQSeverity(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "CRITICAL"
	case types.SeverityHigh:
		return "MAJOR"
	case types.SeverityMedium:
		return "MINOR"
	case types.SeverityLow, types.SeverityInfo:
		return "INFO"
	default:
		return "INFO"
	}
}

func mapSQImpactSeverity(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh:
		return "HIGH"
	case types.SeverityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func estimateEffort(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 60
	case types.SeverityHigh:
		return 30
	case types.SeverityMedium:
		return 15
	default:
		return 5
	}
}
