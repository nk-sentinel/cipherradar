package opengrep

import (
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// DeduplicateFindings merges Pass 1 and Pass 2 findings, removing duplicates.
// A duplicate is defined as: same file + same start line + same algorithm/name.
// When a duplicate is found, the higher-confidence finding is preferred.
// If Pass 2 adds new information (e.g. description from taint flow), it is
// merged into the retained finding.
// The result is deterministic: Pass 1 findings come first (in order), followed
// by non-duplicate Pass 2 findings (in order).
func DeduplicateFindings(pass1, pass2 []types.Finding) []types.Finding {
	if len(pass2) == 0 {
		return pass1
	}

	// Build an index of Pass 1 findings by dedup key.
	type dedupEntry struct {
		index int // index in the result slice
	}
	index := make(map[string]dedupEntry, len(pass1))

	// Start with a copy of Pass 1 findings so we can mutate entries.
	result := make([]types.Finding, len(pass1))
	copy(result, pass1)

	for i, f := range result {
		key := dedupKey(f)
		index[key] = dedupEntry{index: i}
	}

	// Process Pass 2 findings.
	for _, p2 := range pass2 {
		key := dedupKey(p2)

		if entry, exists := index[key]; exists {
			// Duplicate found -- merge.
			existing := &result[entry.index]
			mergeFindings(existing, p2)
		} else {
			// New finding from Pass 2 -- append.
			result = append(result, p2)
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

// mergeFindings merges a Pass 2 finding into an existing finding.
// The higher-confidence finding's fields are preferred for confidence and severity.
// If Pass 2 provides a description not already present, it is appended.
func mergeFindings(existing *types.Finding, p2 types.Finding) {
	// Prefer higher confidence.
	if confidenceRank(p2.Confidence) > confidenceRank(existing.Confidence) {
		existing.Confidence = p2.Confidence
		existing.Severity = p2.Severity
	}

	// If Pass 2 provides a description and the existing one is empty or different,
	// append the Pass 2 description as supplementary information.
	if p2.Description != "" && existing.Description != p2.Description {
		if existing.Description == "" {
			existing.Description = p2.Description
		} else if !strings.Contains(existing.Description, p2.Description) {
			existing.Description = existing.Description + " [Pass 2: " + p2.Description + "]"
		}
	}

	// If Pass 2 provided a rule ID and existing has none, adopt it.
	if existing.RuleID == "" && p2.RuleID != "" {
		existing.RuleID = p2.RuleID
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
