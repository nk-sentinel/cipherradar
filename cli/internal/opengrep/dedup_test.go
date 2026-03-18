package opengrep

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestDeduplicateNoDuplicates(t *testing.T) {
	pass1 := []types.Finding{
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
			Pass:       1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:       "MD5",
			Location:   types.Location{File: "hash.py", StartLine: 5},
			Confidence: types.ConfidenceMedium,
			Pass:       2,
		},
	}

	result := DeduplicateFindings(pass1, pass2)
	if len(result) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result))
	}

	// Verify order: Pass 1 first, then Pass 2.
	if result[0].Name != "AES-256" {
		t.Errorf("expected first finding AES-256, got %q", result[0].Name)
	}
	if result[1].Name != "RSA-2048" {
		t.Errorf("expected second finding RSA-2048, got %q", result[1].Name)
	}
	if result[2].Name != "MD5" {
		t.Errorf("expected third finding MD5, got %q", result[2].Name)
	}
}

func TestDeduplicateExactDuplicate(t *testing.T) {
	pass1 := []types.Finding{
		{
			Name:        "AES-256",
			Location:    types.Location{File: "crypto.py", StartLine: 10},
			Confidence:  types.ConfidenceLow,
			Severity:    types.SeverityMedium,
			Description: "AES-256 usage found",
			Pass:        1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:        "AES-256",
			Location:    types.Location{File: "crypto.py", StartLine: 10},
			Confidence:  types.ConfidenceHigh,
			Severity:    types.SeverityHigh,
			Description: "AES-256 taint analysis confirmed",
			RuleID:      "cbom-python-aes",
			Pass:        2,
		},
	}

	result := DeduplicateFindings(pass1, pass2)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (deduplicated), got %d", len(result))
	}

	// Higher confidence from Pass 2 should be used.
	if result[0].Confidence != types.ConfidenceHigh {
		t.Errorf("expected Confidence=high, got %q", result[0].Confidence)
	}

	// Severity should be updated along with confidence.
	if result[0].Severity != types.SeverityHigh {
		t.Errorf("expected Severity=high, got %q", result[0].Severity)
	}

	// RuleID from Pass 2 should be adopted (Pass 1 had none).
	if result[0].RuleID != "cbom-python-aes" {
		t.Errorf("expected RuleID=cbom-python-aes, got %q", result[0].RuleID)
	}

	// Description should be merged.
	if result[0].Description != "AES-256 usage found [Pass 2: AES-256 taint analysis confirmed]" {
		t.Errorf("unexpected description: %q", result[0].Description)
	}
}

func TestDeduplicatePreferHigherConfidencePass1(t *testing.T) {
	// When Pass 1 has higher confidence, keep Pass 1's confidence.
	pass1 := []types.Finding{
		{
			Name:       "SHA-256",
			Location:   types.Location{File: "hash.py", StartLine: 5},
			Confidence: types.ConfidenceHigh,
			Severity:   types.SeverityMedium,
			Pass:       1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:       "SHA-256",
			Location:   types.Location{File: "hash.py", StartLine: 5},
			Confidence: types.ConfidenceLow,
			Severity:   types.SeverityLow,
			Pass:       2,
		},
	}

	result := DeduplicateFindings(pass1, pass2)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Confidence != types.ConfidenceHigh {
		t.Errorf("expected Pass 1 confidence to be kept (high), got %q", result[0].Confidence)
	}
	if result[0].Severity != types.SeverityMedium {
		t.Errorf("expected Pass 1 severity to be kept (medium), got %q", result[0].Severity)
	}
}

func TestDeduplicateOverlappingDifferentLines(t *testing.T) {
	pass1 := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 10},
			Pass:     1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 25},
			Pass:     2,
		},
	}

	result := DeduplicateFindings(pass1, pass2)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (different lines), got %d", len(result))
	}
}

func TestDeduplicatePass2AddsNewFindings(t *testing.T) {
	pass1 := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 10},
			Pass:     1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:     "hardcoded-key",
			Location: types.Location{File: "crypto.py", StartLine: 15},
			Pass:     2,
		},
		{
			Name:     "weak-random",
			Location: types.Location{File: "utils.py", StartLine: 3},
			Pass:     2,
		},
	}

	result := DeduplicateFindings(pass1, pass2)
	if len(result) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result))
	}

	// Pass 1 finding should come first.
	if result[0].Pass != 1 {
		t.Errorf("expected first finding to be Pass 1, got Pass %d", result[0].Pass)
	}
	// New Pass 2 findings appended.
	if result[1].Pass != 2 || result[1].Name != "hardcoded-key" {
		t.Errorf("expected second finding to be Pass 2 hardcoded-key, got Pass=%d Name=%q", result[1].Pass, result[1].Name)
	}
	if result[2].Pass != 2 || result[2].Name != "weak-random" {
		t.Errorf("expected third finding to be Pass 2 weak-random, got Pass=%d Name=%q", result[2].Pass, result[2].Name)
	}
}

func TestDeduplicateEmptyPass2(t *testing.T) {
	pass1 := []types.Finding{
		{
			Name:     "AES-256",
			Location: types.Location{File: "crypto.py", StartLine: 10},
			Pass:     1,
		},
		{
			Name:     "RSA-2048",
			Location: types.Location{File: "auth.py", StartLine: 20},
			Pass:     1,
		},
	}

	result := DeduplicateFindings(pass1, nil)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings unchanged, got %d", len(result))
	}
	if result[0].Name != "AES-256" || result[1].Name != "RSA-2048" {
		t.Error("Pass 1 findings should be unchanged when Pass 2 is empty")
	}
}

func TestDeduplicateEmptyPass1(t *testing.T) {
	pass2 := []types.Finding{
		{
			Name:     "hardcoded-key",
			Location: types.Location{File: "secret.py", StartLine: 1},
			Pass:     2,
		},
	}

	result := DeduplicateFindings(nil, pass2)
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
	pass1 := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "Crypto.py", StartLine: 10},
			Confidence: types.ConfidenceLow,
			Pass:       1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:       "aes-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceHigh,
			Pass:       2,
		},
	}

	result := DeduplicateFindings(pass1, pass2)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (case-insensitive match), got %d", len(result))
	}
}

func TestDeduplicateDoesNotMutateInput(t *testing.T) {
	pass1 := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceLow,
			Pass:       1,
		},
	}

	pass2 := []types.Finding{
		{
			Name:       "AES-256",
			Location:   types.Location{File: "crypto.py", StartLine: 10},
			Confidence: types.ConfidenceHigh,
			Pass:       2,
		},
	}

	// Save original pass1 confidence.
	origConfidence := pass1[0].Confidence

	_ = DeduplicateFindings(pass1, pass2)

	// Original pass1 slice should not be mutated.
	if pass1[0].Confidence != origConfidence {
		t.Errorf("DeduplicateFindings mutated input pass1 slice: confidence changed from %q to %q",
			origConfidence, pass1[0].Confidence)
	}
}
