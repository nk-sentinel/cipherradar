package joern

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestDeduplicateNoDuplicates(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceHigh,
			Pass:       1,
		},
		{
			Name:       "RSA-2048",
			Location:   types.Location{File: "auth.py", StartLine: 20},
			Confidence: types.ConfidenceMedium,
			Pass:       2,
		},
	}

	pass3 := []types.Finding{
		{
			Name:       "hardcoded-key-flow",
			Location:   types.Location{File: "secret.py", StartLine: 5},
			Confidence: types.ConfidenceHigh,
			Pass:       3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result))
	}

	// Verify order: earlier findings first, then Pass 3.
	if result[0].Name != "AES-256" {
		t.Errorf("expected first finding AES-256, got %q", result[0].Name)
	}
	if result[1].Name != "RSA-2048" {
		t.Errorf("expected second finding RSA-2048, got %q", result[1].Name)
	}
	if result[2].Name != "hardcoded-key-flow" {
		t.Errorf("expected third finding hardcoded-key-flow, got %q", result[2].Name)
	}
}

func TestDeduplicateExactDuplicate(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:        "AES-256",
			Location:    types.Location{File: "crypto.py", StartLine: 10},
			Confidence:  types.ConfidenceLow,
			Severity:    types.SeverityMedium,
			Description: "AES-256 usage found",
			Pass:        1,
		},
	}

	pass3 := []types.Finding{
		{
			Name:        "AES-256",
			Location:    types.Location{File: "crypto.py", StartLine: 10},
			Confidence:  types.ConfidenceHigh,
			Severity:    types.SeverityHigh,
			Description: "AES-256 inter-procedural key flow confirmed",
			RuleID:      "joern-crypto-key-flow",
			Pass:        3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (deduplicated), got %d", len(result))
	}

	// Higher confidence from Pass 3 should be used.
	if result[0].Confidence != types.ConfidenceHigh {
		t.Errorf("expected Confidence=high, got %q", result[0].Confidence)
	}

	// Severity should be updated along with confidence.
	if result[0].Severity != types.SeverityHigh {
		t.Errorf("expected Severity=high, got %q", result[0].Severity)
	}

	// RuleID from Pass 3 should be adopted (earlier had none).
	if result[0].RuleID != "joern-crypto-key-flow" {
		t.Errorf("expected RuleID=joern-crypto-key-flow, got %q", result[0].RuleID)
	}

	// Description should be merged.
	if result[0].Description != "AES-256 usage found [Pass 3: AES-256 inter-procedural key flow confirmed]" {
		t.Errorf("unexpected description: %q", result[0].Description)
	}
}

func TestDeduplicatePreferHigherConfidenceEarlier(t *testing.T) {
	// When earlier pass has higher confidence, keep it.
	earlier := []types.Finding{
		{
			Name:       "SHA-256",
			Location:   types.Location{File: "hash.py", StartLine: 5},
			Confidence: types.ConfidenceHigh,
			Severity:   types.SeverityMedium,
			Pass:       1,
		},
	}

	pass3 := []types.Finding{
		{
			Name:       "SHA-256",
			Location:   types.Location{File: "hash.py", StartLine: 5},
			Confidence: types.ConfidenceLow,
			Severity:   types.SeverityLow,
			Pass:       3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Confidence != types.ConfidenceHigh {
		t.Errorf("expected earlier confidence to be kept (high), got %q", result[0].Confidence)
	}
	if result[0].Severity != types.SeverityMedium {
		t.Errorf("expected earlier severity to be kept (medium), got %q", result[0].Severity)
	}
}

func TestDeduplicateOverlappingDifferentLines(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 10},
			Pass:     1,
		},
	}

	pass3 := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 25},
			Pass:     3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (different lines), got %d", len(result))
	}
}

func TestDeduplicatePass3AddsNewFindings(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 10},
			Pass:     1,
		},
	}

	pass3 := []types.Finding{
		{
			Name:     "hardcoded-key",
			Location: types.Location{File: "crypto.py", StartLine: 15},
			Pass:     3,
		},
		{
			Name:     "secret-propagation",
			Location: types.Location{File: "utils.py", StartLine: 3},
			Pass:     3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result))
	}

	// Earlier findings should come first.
	if result[0].Pass != 1 {
		t.Errorf("expected first finding to be Pass 1, got Pass %d", result[0].Pass)
	}
	// New Pass 3 findings appended.
	if result[1].Pass != 3 || result[1].Name != "hardcoded-key" {
		t.Errorf("expected second finding to be Pass 3 hardcoded-key, got Pass=%d Name=%q", result[1].Pass, result[1].Name)
	}
	if result[2].Pass != 3 || result[2].Name != "secret-propagation" {
		t.Errorf("expected third finding to be Pass 3 secret-propagation, got Pass=%d Name=%q", result[2].Pass, result[2].Name)
	}
}

func TestDeduplicateEmptyPass3(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 10},
			Pass:     1,
		},
		{
			Name:     "RSA-2048",
			Location: types.Location{File: "auth.py", StartLine: 20},
			Pass:     2,
		},
	}

	result := DeduplicateFindings(earlier, nil)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings unchanged, got %d", len(result))
	}
	if result[0].Name != "AES-256" || result[1].Name != "RSA-2048" {
		t.Error("earlier findings should be unchanged when Pass 3 is empty")
	}
}

func TestDeduplicateEmptyEarlier(t *testing.T) {
	pass3 := []types.Finding{
		{
			Name:     "hardcoded-key",
			Location: types.Location{File: "secret.py", StartLine: 1},
			Pass:     3,
		},
	}

	result := DeduplicateFindings(nil, pass3)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Name != "hardcoded-key" {
		t.Errorf("expected finding name=hardcoded-key, got %q", result[0].Name)
	}
}

func TestDeduplicateBothEmpty(t *testing.T) {
	result := DeduplicateFindings(nil, nil)
	if result != nil {
		t.Errorf("expected nil for both empty, got %v", result)
	}
}

func TestDeduplicateCaseInsensitiveKeyMatch(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "Crypto.py", StartLine: 10},
			Confidence: types.ConfidenceLow,
			Pass:       1,
		},
	}

	pass3 := []types.Finding{
		{
			Name:       "aes-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceHigh,
			Pass:       3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (case-insensitive match), got %d", len(result))
	}
}

func TestDeduplicateDoesNotMutateInput(t *testing.T) {
	earlier := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceLow,
			Pass:       1,
		},
	}

	pass3 := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceHigh,
			Pass:       3,
		},
	}

	// Save original confidence.
	origConfidence := earlier[0].Confidence

	_ = DeduplicateFindings(earlier, pass3)

	// Original earlier slice should not be mutated.
	if earlier[0].Confidence != origConfidence {
		t.Errorf("DeduplicateFindings mutated input earlier slice: confidence changed from %q to %q",
			origConfidence, earlier[0].Confidence)
	}
}

func TestDeduplicateMergesPass2AndPass3(t *testing.T) {
	// Test that dedup works when earlier findings contain both Pass 1 and Pass 2.
	earlier := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceMedium,
			Pass:       1,
		},
		{
			Name:        "hardcoded-key",
			Location:    types.Location{File: "crypto.py", StartLine: 15},
			Confidence:  types.ConfidenceMedium,
			Description: "Taint analysis: hardcoded key flows to cipher",
			Pass:        2,
		},
	}

	pass3 := []types.Finding{
		{
			Name:        "hardcoded-key",
			Location:    types.Location{File: "crypto.py", StartLine: 15},
			Confidence:  types.ConfidenceHigh,
			Description: "Inter-procedural: hardcoded key propagates across 3 functions",
			RuleID:      "joern-hardcoded-secret-flow",
			Pass:        3,
		},
	}

	result := DeduplicateFindings(earlier, pass3)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result))
	}

	// The hardcoded-key finding should be merged with Pass 3.
	if result[1].Confidence != types.ConfidenceHigh {
		t.Errorf("expected merged confidence=high, got %q", result[1].Confidence)
	}
	if result[1].RuleID != "joern-hardcoded-secret-flow" {
		t.Errorf("expected merged RuleID=joern-hardcoded-secret-flow, got %q", result[1].RuleID)
	}
}
