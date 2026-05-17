// Package explain provides the data model behind `cradar rules list` and
// `cradar rules explain <id>`. It parses the embedded OpenGrep YAML rule
// files (the same files shipped to the Pass 2 scanner) to build a canonical
// summary of every rule, and loads optional human-authored markdown docs
// from docs/*.md to enrich the explain output.
//
// Scope note: explain is metadata-driven. We do NOT run the rule — we just
// surface what the rule's author declared about it (category, maturity,
// noise, severity, message). When a dedicated docs/{id}.md seed is present
// it is appended verbatim after the auto-generated summary.
package explain

import (
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nk-sentinel/cipherradar/cli/internal/rules"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

//go:embed docs/*.md
var docsFS embed.FS

// Rule is the canonical view of a single OpenGrep rule for the `rules`
// command family. Fields are a subset of the YAML metadata + a few fields
// the rule author declared at the top level (ID, severity, languages).
type Rule struct {
	ID             string
	File           string // source YAML file (e.g. "python.yml")
	Languages      []string
	Severity       string
	Message        string
	Category       types.Category
	Maturity       types.Maturity
	NoiseRisk      types.NoiseRisk
	DefaultEnabled bool
}

// yamlRule mirrors only the fields we need from a YAML rule entry. Extra
// fields (patterns, pattern-either, etc.) are ignored by yaml.v3 decoding.
type yamlRule struct {
	ID        string     `yaml:"id"`
	Severity  string     `yaml:"severity"`
	Languages []string   `yaml:"languages"`
	Message   string     `yaml:"message"`
	Metadata  yamlRuleMD `yaml:"metadata"`
}

type yamlRuleMD struct {
	Category       string `yaml:"category"`
	Maturity       string `yaml:"maturity"`
	NoiseRisk      string `yaml:"noise_risk"`
	DefaultEnabled *bool  `yaml:"default_enabled"`
}

// yamlFile is the top-level structure of each embedded rules YAML file.
type yamlFile struct {
	Rules []yamlRule `yaml:"rules"`
}

// All returns every rule parsed from the embedded YAML corpus, sorted by
// ID for stable output. Parse errors on individual files are surfaced so
// operators can fix a malformed rule locally.
func All() ([]Rule, error) {
	files, err := rules.RuleFiles()
	if err != nil {
		return nil, fmt.Errorf("listing embedded rules: %w", err)
	}

	var out []Rule
	for _, name := range files {
		rs, err := parseFile(name)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		out = append(out, rs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// FindByID returns the rule with the given ID, or (nil, nil) if no such
// rule exists in the embedded corpus.
func FindByID(id string) (*Rule, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}

// Doc returns the embedded markdown documentation for the given rule ID,
// or an empty string if no such doc exists. Missing docs are expected —
// the `explain` command falls back to the YAML-derived summary.
func Doc(id string) string {
	data, err := docsFS.ReadFile(filepath.Join("docs", id+".md"))
	if err != nil {
		return ""
	}
	return string(data)
}

// parseFile parses a single embedded rule YAML file into []Rule. Defaults
// mirror the permissive fallbacks in opengrep/parser.go so list output is
// consistent with what the filter engine actually sees at scan time.
func parseFile(name string) ([]Rule, error) {
	data, err := rules.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var y yamlFile
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, err
	}

	out := make([]Rule, 0, len(y.Rules))
	for _, r := range y.Rules {
		out = append(out, Rule{
			ID:             r.ID,
			File:           name,
			Languages:      append([]string(nil), r.Languages...),
			Severity:       strings.ToLower(r.Severity),
			Message:        strings.TrimSpace(r.Message),
			Category:       mapCategory(r.Metadata.Category),
			Maturity:       mapMaturity(r.Metadata.Maturity),
			NoiseRisk:      mapNoiseRisk(r.Metadata.NoiseRisk),
			DefaultEnabled: mapDefaultEnabled(r.Metadata.DefaultEnabled),
		})
	}
	return out, nil
}

func mapCategory(s string) types.Category {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "inventory":
		return types.CategoryInventory
	default:
		// Empty or unknown → security (mirrors rulefilter permissive default).
		return types.CategorySecurity
	}
}

func mapMaturity(s string) types.Maturity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "experimental":
		return types.MaturityExperimental
	case "deprecated":
		return types.MaturityDeprecated
	default:
		return types.MaturityStable
	}
}

func mapNoiseRisk(s string) types.NoiseRisk {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return types.NoiseRiskHigh
	case "med", "medium":
		return types.NoiseRiskMedium
	default:
		return types.NoiseRiskLow
	}
}

func mapDefaultEnabled(p *bool) bool {
	// nil → true (rule predates field). Explicit false stays false.
	if p == nil {
		return true
	}
	return *p
}
