package joern

import (
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// DeduplicateFindings merges earlier-pass findings (Pass 1+2) with Pass 3 findings,
// removing duplicates. A duplicate is defined as: same file + same start line + same
// algorithm/name. When a duplicate is found, the higher-confidence finding is preferred.
// If Pass 3 adds new information (e.g. taint flow description), it is merged into the
// retained finding.
// The result is deterministic: earlier findings come first (in order), followed by
// non-duplicate Pass 3 findings (in order).
func DeduplicateFindings(earlier, pass3 []types.Finding) []types.Finding {
	if len(pass3) == 0 {
		return earlier
	}

	// Build an index of earlier findings by dedup key.
	type dedupEntry struct {
		index int // index in the result slice
	}
	index := make(map[string]dedupEntry, len(earlier))

	// Start with a copy of earlier findings so we can mutate entries.
	result := make([]types.Finding, len(earlier))
	copy(result, earlier)

	for i, f := range result {
		key := dedupKey(f)
		index[key] = dedupEntry{index: i}
	}

	// Process Pass 3 findings.
	for _, p3 := range pass3 {
		key := dedupKey(p3)

		if entry, exists := index[key]; exists {
			// Duplicate found -- merge.
			existing := &result[entry.index]
			mergeFindings(existing, p3)
		} else {
			// New finding from Pass 3 -- append.
			result = append(result, p3)
			index[key] = dedupEntry{index: len(result) - 1}
		}
	}

	return result
}

// dedupKey produces a deterministic key for deduplication.
// Format: "file:startline:name" (all lowercased).
func dedupKey(f types.Finding) string {
	name := strings.ToLower(strings.TrimSpace(f.Name))
	file := strings.ToLower(strings.TrimSpace(f.Location.File))
	return fmt.Sprintf("%s:%d:%s", file, f.Location.StartLine, name)
}

// mergeFindings merges a Pass 3 finding into an existing finding.
// The higher-confidence finding's fields are preferred for confidence and severity.
// If Pass 3 provides a description not already present, it is appended.
func mergeFindings(existing *types.Finding, p3 types.Finding) {
	// Prefer higher confidence.
	if confidenceRank(p3.Confidence) > confidenceRank(existing.Confidence) {
		existing.Confidence = p3.Confidence
		existing.Severity = p3.Severity
	}

	// If Pass 3 provides a description and the existing one is empty or different,
	// append the Pass 3 description as supplementary information.
	if p3.Description != "" && existing.Description != p3.Description {
		if existing.Description == "" {
			existing.Description = p3.Description
		} else if !strings.Contains(existing.Description, p3.Description) {
			existing.Description = existing.Description + " [Pass 3: " + p3.Description + "]"
		}
	}

	// If Pass 3 provided a rule ID and existing has none, adopt it.
	if existing.RuleID == "" && p3.RuleID != "" {
		existing.RuleID = p3.RuleID
	}
}

// confidenceRank returns a numeric rank for confidence values (higher = more confident).
func confidenceRank(c types.Confidence) int {
	switch c {
	case types.ConfidenceHigh:
		return 3
	case types.ConfidenceMedium:
		return 2
	case types.ConfidenceLow:
		return 1
	default:
		return 0
	}
}
