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
//
// DefaultEnabled uses *bool so we can distinguish "unset" (nil) from
// "explicitly false". Portal-synced rules pre-dating this field are treated
// as default_enabled: true (see mapDefaultEnabled).
type opengrepMetadata struct {
	CbomAssetType   string `json:"cbom-asset-type"`
	Confidence      string `json:"confidence"`
	QuantumRelevant bool   `json:"quantum-relevant"`
	Category        string `json:"category"`
	Maturity        string `json:"maturity"`
	NoiseRisk       string `json:"noise_risk"`
	DefaultEnabled  *bool  `json:"default_enabled"`
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

	// Bug 6: when opengrep refused to load any rules / scan any paths it
	// returns results=[] and a populated errors[] — silently returning 0
	// findings used to mask broken rule files. Surface the messages.
	if len(output.Results) == 0 && len(output.Errors) > 0 {
		msgs := make([]string, 0, len(output.Errors))
		for _, e := range output.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("opengrep produced no results, %d errors: %s",
			len(output.Errors), strings.Join(msgs, "; "))
	}

	findings := make([]types.Finding, 0, len(output.Results))
	for _, r := range output.Results {
		canonicalID := stripCheckIDNamespace(r.CheckID)
		f := types.Finding{
			RuleID:         canonicalID,
			Pass:           2,
			Description:    r.Extra.Message,
			Severity:       mapSeverity(r.Extra.Severity),
			Confidence:     mapConfidence(r.Extra.Metadata.Confidence),
			AssetType:      mapAssetType(r.Extra.Metadata.CbomAssetType),
			Category:       mapCategory(r.Extra.Metadata.Category),
			Maturity:       mapMaturity(r.Extra.Metadata.Maturity),
			NoiseRisk:      mapNoiseRisk(r.Extra.Metadata.NoiseRisk),
			DefaultEnabled: mapDefaultEnabled(r.Extra.Metadata.DefaultEnabled),
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
		f.Name = deriveNameFromCheckID(canonicalID)

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

// mapCategory maps the YAML "category" field to a types.Category. An unset or
// unrecognized value defaults to CategorySecurity (conservative: include in
// default scan). Rule authors should set this explicitly.
func mapCategory(s string) types.Category {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "inventory":
		return types.CategoryInventory
	case "security":
		return types.CategorySecurity
	default:
		return types.CategorySecurity
	}
}

// mapMaturity maps the YAML "maturity" field to a types.Maturity. An unset or
// unrecognized value defaults to MaturityStable (forward-compat: portal-synced
// rules pre-dating this field are treated as stable production rules).
func mapMaturity(s string) types.Maturity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "experimental":
		return types.MaturityExperimental
	case "stable":
		return types.MaturityStable
	case "deprecated":
		return types.MaturityDeprecated
	default:
		return types.MaturityStable
	}
}

// mapNoiseRisk maps the YAML "noise_risk" field to a types.NoiseRisk. An unset
// or unrecognized value defaults to NoiseRiskLow.
func mapNoiseRisk(s string) types.NoiseRisk {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return types.NoiseRiskLow
	case "med", "medium":
		return types.NoiseRiskMedium
	case "high":
		return types.NoiseRiskHigh
	default:
		return types.NoiseRiskLow
	}
}

// mapDefaultEnabled maps the YAML "default_enabled" field to a bool. nil (unset)
// maps to true for forward-compat with rules authored before this field existed.
func mapDefaultEnabled(b *bool) bool {
	if b == nil {
		return true
	}
	return *b
}

// stripCheckIDNamespace removes the directory-derived namespace prefix that
// OpenGrep adds when invoked with --config <dir>. The check_id format is
// "<dot.separated.namespace>.cbom-<lang>-<id>"; real rule IDs use dashes
// (no dots), so taking everything after the last dot is safe.
//
// When OpenGrep is invoked with per-file --config <file>, the prefix is
// absent and this is a no-op.
func stripCheckIDNamespace(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}

// deriveNameFromCheckID attempts to extract a human-readable name from the check_id.
// For example, "cbom-python-hardcoded-key" becomes "hardcoded-key".
//
// Per-language prefixes are listed longest-first so the bare "cbom-" fallback
// only matches when no language prefix applies.
func deriveNameFromCheckID(checkID string) string {
	// Strip common prefixes.
	name := checkID
	for _, prefix := range []string{
		"cbom-javascript-",
		"cbom-python-",
		"cbom-kotlin-",
		"cbom-swift-",
		"cbom-java-",
		"cbom-ruby-",
		"cbom-rust-",
		"cbom-dart-",
		"cbom-csharp-",
		"cbom-cpp-",
		"cbom-php-",
		"cbom-js-",
		"cbom-go-",
		"cbom-",
	} {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			break
		}
	}
	return name
}
