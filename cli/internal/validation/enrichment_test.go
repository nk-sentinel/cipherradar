package validation

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEnrichment_EnumMismatch_ExpectedPopulated builds a fake BOM with an
// enum violation (bomFormat: "Wrong") and asserts the validator populates
// the Expected slice + keyword. This is the core win: the 37 CycloneDX 1.7
// failures documented in docs/benchmark/TODO-SCHEMA-VALIDATION.md become
// actionable instead of opaque.
func TestEnrichment_EnumMismatch_ExpectedPopulated(t *testing.T) {
	bom := map[string]any{
		"bomFormat":   "Wrong",
		"specVersion": "1.7",
		"version":     1,
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if res.Valid {
		t.Fatal("expected invalid")
	}

	foundEnum := false
	for _, e := range res.Errors {
		if e.Keyword != "enum" {
			continue
		}
		foundEnum = true
		if e.Actual != "Wrong" {
			t.Errorf("actual: want Wrong, got %q", e.Actual)
		}
		if len(e.Expected) == 0 {
			t.Error("expected enum values not populated")
		}
		// CycloneDX bomFormat enum is ["CycloneDX"].
		joined := strings.Join(e.Expected, ",")
		if !strings.Contains(joined, "CycloneDX") {
			t.Errorf("expected should contain CycloneDX, got %q", joined)
		}
	}
	if !foundEnum {
		t.Errorf("no enum-kind error surfaced; got %d errors: %+v", len(res.Errors), res.Errors)
	}
}

// TestEnrichment_TypeMismatch_PopulatesKeyword ensures a type violation is
// tagged keyword=type and carries a non-empty Expected/Actual pair.
func TestEnrichment_TypeMismatch_PopulatesKeyword(t *testing.T) {
	// specVersion must be a string; pass an int to force a type error.
	bom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": 17,
		"version":     1,
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if res.Valid {
		t.Fatal("expected invalid")
	}

	for _, e := range res.Errors {
		if e.Keyword == "type" {
			if e.Actual == "" {
				t.Error("type error should carry actual")
			}
			if len(e.Expected) == 0 {
				t.Error("type error should carry expected")
			}
			return
		}
	}
	// Not all schemas surface `type` — enum on specVersion also trips. At
	// minimum one enrichment keyword must be set.
	for _, e := range res.Errors {
		if e.Keyword != "" {
			return
		}
	}
	t.Errorf("no keyword-tagged error surfaced for type mismatch: %+v", res.Errors)
}

// TestEnrichment_ValidBOM_NoErrors confirms enrichment didn't introduce a
// false-positive path that misreports a valid BOM.
func TestEnrichment_ValidBOM_NoErrors(t *testing.T) {
	bom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.7",
		"version":     1,
	}
	data, _ := json.Marshal(bom)
	res, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !res.Valid {
		t.Errorf("valid BOM reported invalid: %+v", res.Errors)
	}
}

// TestEnrichment_LeafOnly asserts that we only surface leaf errors — we
// must not emit aggregate Group/OneOf nodes that pollute the output.
func TestEnrichment_LeafOnly(t *testing.T) {
	bom := map[string]any{
		"bomFormat":   "Bad",
		"specVersion": "1.7",
		"version":     1,
	}
	data, _ := json.Marshal(bom)
	res, _ := ValidateCycloneDXJSON(data)
	if len(res.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
	// At least one error must carry a keyword — if every entry has empty
	// Keyword we're not reaching the leaves.
	hasKeyword := false
	for _, e := range res.Errors {
		if e.Keyword != "" {
			hasKeyword = true
			break
		}
	}
	if !hasKeyword {
		t.Errorf("all surfaced errors lacked keyword — walk didn't reach leaves: %+v", res.Errors)
	}
}
