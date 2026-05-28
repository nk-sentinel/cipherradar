// Package rulefilter applies rule-lifecycle and category filters to scan
// findings. It runs after scanning + dedup and before output writers, so
// every writer sees the same filtered set.
//
// Filtering is driven by the lifecycle metadata added to types.Finding in
// Phase A (Category, Maturity, NoiseRisk, DefaultEnabled) and the CLI flags
// wired in Phase C of the rule-lifecycle initiative (see docs/cli-improvements-plan.md).
//
// Precedence (applied in order):
//
//  1. Start set — if Options.Rules is non-empty, candidates are restricted to
//     exactly that rule-id set (explicit whitelist). Otherwise candidates are
//     findings whose rule has DefaultEnabled=true AND Maturity != deprecated.
//  2. Category filter — keep only findings whose Category is in Options.Categories
//     (if set). --only-inventory / --only-security are sugar for this.
//  3. Additive opt-ins — --include-experimental / --include-noisy /
//     --include-rule bring back findings that step 1 excluded.
//  4. Final subtraction — --disable-rule removes specific rule ids regardless
//     of prior inclusion.
//
// Deprecated rules that survive filtering trigger a one-shot stderr warning
// unless Options.IncludeDeprecated is true (ADR-034, 2 minor releases).
package rulefilter

import (
	"fmt"
	"io"
	"sort"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Options describes a filter run. Fields mirror the CLI flags; an empty/zero
// Options represents "default scan" (runs stable + default_enabled rules only).
type Options struct {
	// Categories restricts findings to these rule categories. Nil/empty =
	// both inventory and security.
	Categories []types.Category
	// Rules is an explicit include list of rule IDs. When non-empty, this
	// OVERRIDES the default start set — only findings whose rule_id is in
	// this list are considered (before step 2 applies).
	Rules []string
	// DisabledRules removes findings with these rule IDs as the final step.
	DisabledRules []string
	// IncludeExperimental re-includes findings whose rule has
	// Maturity == MaturityExperimental.
	IncludeExperimental bool
	// IncludeNoisy re-includes findings whose rule has NoiseRisk == NoiseRiskHigh.
	IncludeNoisy bool
	// IncludeDeprecated silences the deprecation warning. The rule still runs
	// either way (deprecation only affects logging).
	IncludeDeprecated bool
	// IncludeRules re-includes specific rule IDs regardless of maturity/noise
	// (narrower than IncludeExperimental/IncludeNoisy — per-rule opt-in).
	IncludeRules []string
}

// Stats reports what the filter did for a single invocation. Returned
// alongside the filtered findings so callers can log / surface counts.
type Stats struct {
	// Input is the number of findings fed in.
	Input int
	// Kept is the number of findings that passed all filters.
	Kept int
	// DroppedByCategory is the number dropped for being in the wrong category.
	DroppedByCategory int
	// DroppedByMaturity is the number dropped because their rule was
	// experimental or deprecated-not-included without opt-in.
	DroppedByMaturity int
	// DroppedByDefault is the number dropped because default_enabled was false
	// and no include flag/list brought them back.
	DroppedByDefault int
	// DroppedByDisable is the number removed by --disable-rule.
	DroppedByDisable int
	// DroppedByRulesAllowlist is the number dropped because --rules was set
	// and their rule_id wasn't in the list.
	DroppedByRulesAllowlist int
	// DeprecatedRulesSeen lists rule IDs of deprecated rules that still
	// produced findings. Used to emit a single aggregated warning.
	DeprecatedRulesSeen []string
}

// Apply filters findings per opts and returns the kept set + stats.
// Findings are returned in their original order; filtering is order-stable.
func Apply(findings []types.Finding, opts Options) ([]types.Finding, Stats) {
	stats := Stats{Input: len(findings)}
	if len(findings) == 0 {
		return nil, stats
	}

	allowSet := toSet(opts.Rules)
	disableSet := toSet(opts.DisabledRules)
	includeRuleSet := toSet(opts.IncludeRules)
	catSet := categorySet(opts.Categories)

	// Track deprecated rule ids we encounter so we can warn once per rule.
	deprecatedSeen := map[string]struct{}{}

	kept := make([]types.Finding, 0, len(findings))
	for _, orig := range findings {
		// Pass 1 scanners (tree-sitter) and other non-YAML-rule sources may
		// emit findings without lifecycle metadata. Treat "empty Maturity"
		// as the pre-lifecycle signal and apply permissive defaults FOR
		// FILTER DECISIONS ONLY — the original finding is what gets appended
		// to kept, so downstream writers see the unmodified scanner output.
		f := normalizeLifecycle(orig)
		// Step 1: start set — either explicit allowlist, or default rules.
		if len(allowSet) > 0 {
			if _, ok := allowSet[f.RuleID]; !ok {
				// Not in --rules list. Check per-rule opt-in before dropping.
				if _, opted := includeRuleSet[f.RuleID]; !opted {
					stats.DroppedByRulesAllowlist++
					continue
				}
			}
		} else {
			// No explicit allowlist — apply default gate.
			if !isDefaultKeep(f, opts, includeRuleSet) {
				// Bucket the drop reason for better stats.
				if f.Maturity == types.MaturityExperimental {
					stats.DroppedByMaturity++
				} else if f.Maturity == types.MaturityDeprecated {
					stats.DroppedByMaturity++
				} else if !f.DefaultEnabled {
					stats.DroppedByDefault++
				} else if f.NoiseRisk == types.NoiseRiskHigh && !opts.IncludeNoisy {
					stats.DroppedByDefault++
				} else {
					stats.DroppedByDefault++
				}
				continue
			}
		}

		// Step 2: category filter.
		//
		// Dual-category semantics: a finding's rule Category is its PRIMARY
		// classification, but a finding that carries a concrete crypto asset
		// identity (AssetType set) is ALSO part of the inventory regardless of
		// whether its rule is tagged security. This makes --only-inventory a
		// complete asset list — weak/broken algorithms (MD5, DES, RC4), which
		// ClassifyRule deliberately tags security, still appear in the inventory
		// because they ARE crypto assets. --only-security is unchanged.
		if len(catSet) > 0 {
			if _, ok := catSet[f.Category]; !ok {
				_, wantInventory := catSet[types.CategoryInventory]
				if !(wantInventory && hasAssetIdentity(f)) {
					stats.DroppedByCategory++
					continue
				}
			}
		}

		// Step 4: --disable-rule final subtraction (trumps includes).
		if _, blocked := disableSet[f.RuleID]; blocked {
			stats.DroppedByDisable++
			continue
		}

		// Survived all filters — keep the ORIGINAL finding so downstream
		// writers see unmodified scanner output (normalized metadata is a
		// filter-local concept and should not leak into the CBOM/SARIF).
		if f.Maturity == types.MaturityDeprecated {
			deprecatedSeen[orig.RuleID] = struct{}{}
		}
		kept = append(kept, orig)
	}

	stats.Kept = len(kept)
	if len(deprecatedSeen) > 0 {
		ids := make([]string, 0, len(deprecatedSeen))
		for id := range deprecatedSeen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		stats.DeprecatedRulesSeen = ids
	}
	return kept, stats
}

// isDefaultKeep returns true if a finding passes the default keep gate (step 1
// when no explicit --rules allowlist is set). Applied per-finding, since the
// per-finding metadata is already populated by the parser.
func isDefaultKeep(f types.Finding, opts Options, includeRuleSet map[string]struct{}) bool {
	// Per-rule opt-in short-circuits every gate except --disable-rule.
	if _, ok := includeRuleSet[f.RuleID]; ok {
		return true
	}

	// Maturity gate: deprecated rules run (with warning) unless the user
	// explicitly disabled them; experimental rules require --include-experimental.
	switch f.Maturity {
	case types.MaturityExperimental:
		if !opts.IncludeExperimental {
			return false
		}
	case types.MaturityDeprecated:
		// Deprecated rules still execute — the IncludeDeprecated flag only
		// silences the warning. Fall through to default_enabled/noise gates.
	}

	// default_enabled gate: rule authors opt rules out of the default scan
	// by setting default_enabled: false. A user can override with --rules,
	// --include-rule, or --include-experimental / --include-noisy for the
	// relevant class.
	if !f.DefaultEnabled {
		if f.NoiseRisk == types.NoiseRiskHigh && opts.IncludeNoisy {
			// --include-noisy re-enables default-off noisy rules.
			return true
		}
		return false
	}

	// Noise gate: even a default-enabled rule can be silenced by marking it
	// NoiseRiskHigh, which forces --include-noisy. (Rule authors who set
	// noise_risk:high should also set default_enabled:false; this branch
	// protects against inconsistent metadata.)
	if f.NoiseRisk == types.NoiseRiskHigh && !opts.IncludeNoisy {
		return false
	}

	return true
}

// hasAssetIdentity reports whether a finding carries a concrete cryptographic
// asset identity (algorithm, protocol, certificate, related-crypto-material).
// Such findings belong in the inventory even when their rule is categorized
// security, so --only-inventory yields a complete CBOM asset list.
func hasAssetIdentity(f types.Finding) bool {
	switch f.AssetType {
	case types.AssetAlgorithm, types.AssetProtocol,
		types.AssetCertificate, types.AssetRelatedCryptoMaterial:
		return true
	default:
		return false
	}
}

// WarnDeprecated writes an aggregated stderr warning for deprecated rules
// that produced findings. No-op when the list is empty or IncludeDeprecated
// was set. Caller decides the writer (normally os.Stderr; tests use a buffer).
func WarnDeprecated(w io.Writer, stats Stats, includeDeprecated bool) {
	if includeDeprecated || len(stats.DeprecatedRulesSeen) == 0 || w == nil {
		return
	}
	fmt.Fprintf(w,
		"WARNING: %d deprecated rule(s) fired this scan — they will be removed in 2 minor releases (ADR-034):\n",
		len(stats.DeprecatedRulesSeen))
	for _, id := range stats.DeprecatedRulesSeen {
		fmt.Fprintf(w, "  - %s\n", id)
	}
	fmt.Fprintln(w, "Pass --include-deprecated to silence this warning.")
}

// normalizeLifecycle fills in permissive defaults for findings that arrive
// without lifecycle metadata. The signal for "pre-lifecycle" is an empty
// Maturity field — if it's set, we trust all other lifecycle fields too.
//
// Defaults (permissive so Pass 1 / pre-lifecycle findings keep flowing):
//
//	Category       → CategorySecurity  (conservative — included in both --only-* filters)
//	Maturity       → MaturityStable
//	NoiseRisk      → NoiseRiskLow
//	DefaultEnabled → true              (pre-lifecycle findings ran by default)
//
// The caller is expected to use this view for DECISIONS only and to append
// the original finding to the kept set so the CBOM output is unchanged.
func normalizeLifecycle(f types.Finding) types.Finding {
	if f.Maturity != "" {
		return f
	}
	if f.Category == "" {
		f.Category = types.CategorySecurity
	}
	f.Maturity = types.MaturityStable
	if f.NoiseRisk == "" {
		f.NoiseRisk = types.NoiseRiskLow
	}
	f.DefaultEnabled = true
	return f
}

// toSet converts a slice to a set for O(1) membership checks. Empty input
// returns a nil map — membership tests against a nil map return false.
func toSet(xs []string) map[string]struct{} {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x != "" {
			m[x] = struct{}{}
		}
	}
	return m
}

// categorySet converts []Category to a set.
func categorySet(xs []types.Category) map[types.Category]struct{} {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[types.Category]struct{}, len(xs))
	for _, x := range xs {
		if x != "" {
			m[x] = struct{}{}
		}
	}
	return m
}
