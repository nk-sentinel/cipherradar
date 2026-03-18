package validation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestSchemaIsEmbedded(t *testing.T) {
	if len(schemaBytes) == 0 {
		t.Fatal("embedded schema bytes should not be empty")
	}
	// Verify it starts with a valid JSON object.
	if schemaBytes[0] != '{' {
		t.Fatal("embedded schema should start with '{'")
	}
}

func TestValidateCycloneDXJSON_ValidMinimalBOM(t *testing.T) {
	bom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.7",
		"version":     1,
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid, got invalid with errors: %v", result.Errors)
	}
}

func TestValidateCycloneDXJSON_ConvertScanResultOutput(t *testing.T) {
	scanResult := &types.ScanResult{
		Target:       "/tmp/test-project",
		StartTime:    time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC),
		EndTime:      time.Date(2026, 3, 18, 12, 0, 2, 0, time.UTC),
		PassesRun:    []int{1},
		FilesScanned: 5,
		Findings: []types.Finding{
			{
				ID:        "FIND-001",
				AssetType: types.AssetAlgorithm,
				Name:      "AES-256-CBC",
				Location: types.Location{
					File:      "crypto.py",
					StartLine: 7,
					StartCol:  5,
				},
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "aes",
					Mode:            "cbc",
					KeySize:         256,
					CryptoFunctions: []string{"encrypt"},
				},
				Description: "AES-256 in CBC mode",
				RuleID:      "cbom-python-cipher-aes",
				Pass:        1,
			},
			{
				ID:        "FIND-002",
				AssetType: types.AssetProtocol,
				Name:      "TLS 1.2",
				Location: types.Location{
					File:      "ssl_usage.py",
					StartLine: 4,
					StartCol:  10,
				},
				Severity:   types.SeverityLow,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType:    "tls",
					ProtocolVersion: "1.2",
					CipherSuites:   []string{"TLS_AES_256_GCM_SHA384"},
				},
				Description: "TLS 1.2 protocol usage",
				RuleID:      "cbom-python-ssl-context",
				Pass:        1,
			},
			{
				ID:        "FIND-003",
				AssetType: types.AssetRelatedCryptoMaterial,
				Name:      "RSA Private Key",
				Location: types.Location{
					File:      "keys.py",
					StartLine: 22,
					StartCol:  3,
				},
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					MaterialType: "private-key",
					MaterialSize: 2048,
					State:        "active",
				},
				Description: "RSA private key generation",
				RuleID:      "cbom-python-rsa-keygen",
				Pass:        1,
			},
		},
	}

	bom := output.ConvertScanResult(scanResult)
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		for _, e := range result.Errors {
			t.Logf("  %s: %s", e.Path, e.Message)
		}
		t.Errorf("expected valid, got %d errors", len(result.Errors))
	}
}

func TestValidateCycloneDXJSON_MissingBomFormat(t *testing.T) {
	bom := map[string]interface{}{
		"specVersion": "1.7",
		"version":     1,
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected validation to fail for missing bomFormat")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one validation error")
	}

	// Check that an error mentions the missing required field.
	found := false
	for _, e := range result.Errors {
		if e.Path == "/" || e.Path == "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a root-level error for missing bomFormat")
	}
}

func TestValidateCycloneDXJSON_WrongSpecVersionType(t *testing.T) {
	// The CycloneDX 1.7 schema requires specVersion to be a string.
	// Using a numeric value should fail validation.
	bom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": 1.7,
		"version":     1,
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected validation to fail for wrong specVersion type")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one validation error")
	}
}

func TestValidateCycloneDXJSON_MissingSpecVersion(t *testing.T) {
	// specVersion is required by the schema.
	bom := map[string]interface{}{
		"bomFormat": "CycloneDX",
		"version":   1,
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected validation to fail for missing specVersion")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one validation error")
	}
}

func TestValidateCycloneDXJSON_InvalidComponentType(t *testing.T) {
	bom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.7",
		"version":     1,
		"components": []interface{}{
			map[string]interface{}{
				"type": "not-a-valid-type",
				"name": "test",
			},
		},
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected validation to fail for invalid component type")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one validation error")
	}
}

func TestValidateCycloneDXJSON_EmptyJSON(t *testing.T) {
	_, err := ValidateCycloneDXJSON([]byte{})
	if err == nil {
		t.Error("expected error for empty JSON data")
	}
}

func TestValidateCycloneDXJSON_NonJSON(t *testing.T) {
	_, err := ValidateCycloneDXJSON([]byte("this is not json"))
	if err == nil {
		t.Error("expected error for non-JSON data")
	}
}

func TestValidateCycloneDXJSON_EmptyFindings(t *testing.T) {
	scanResult := &types.ScanResult{
		Target:       "/tmp/empty",
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		PassesRun:    []int{1},
		FilesScanned: 0,
	}

	bom := output.ConvertScanResult(scanResult)
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := ValidateCycloneDXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		for _, e := range result.Errors {
			t.Logf("  %s: %s", e.Path, e.Message)
		}
		t.Errorf("expected valid, got %d errors", len(result.Errors))
	}
}
