package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// newSARIFTestScanResult creates a ScanResult with mixed findings for SARIF tests.
func newSARIFTestScanResult() *types.ScanResult {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	return &types.ScanResult{
		Target:       "/tmp/test-project",
		StartTime:    now,
		EndTime:      now.Add(2 * time.Second),
		PassesRun:    []int{1, 2},
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
					EndLine:   7,
					EndCol:    30,
				},
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "aes",
					Mode:            "cbc",
					KeySize:         256,
					QuantumStatus:   types.QuantumVulnerable,
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
					QuantumStatus:   types.QuantumVulnerable,
				},
				Description: "TLS 1.2 protocol usage",
				RuleID:      "cbom-python-ssl-context",
				Pass:        1,
			},
			{
				ID:        "FIND-003",
				AssetType: types.AssetCertificate,
				Name:      "X.509 Certificate",
				Location: types.Location{
					File:      "certs.py",
					StartLine: 15,
					StartCol:  1,
				},
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					SubjectName:       "CN=example.com",
					IssuerName:        "CN=CA",
					NotValidBefore:    "2025-01-01T00:00:00Z",
					NotValidAfter:     "2026-01-01T00:00:00Z",
					CertificateFormat: "X.509",
					QuantumStatus:     types.QuantumUnknown,
				},
				Description: "X.509 certificate",
				RuleID:      "cbom-python-cert",
				Pass:        1,
			},
			{
				ID:        "FIND-004",
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
					MaterialType:  "private-key",
					MaterialSize:  2048,
					State:         "active",
					QuantumStatus: types.QuantumVulnerable,
				},
				Description: "RSA private key generation",
				RuleID:      "cbom-python-rsa-keygen",
				Pass:        2,
			},
			{
				ID:        "FIND-005",
				AssetType: types.AssetAlgorithm,
				Name:      "MD5",
				Location: types.Location{
					File:      "hash.py",
					StartLine: 3,
					StartCol:  1,
				},
				Severity:   types.SeverityCritical,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "hash",
					AlgorithmFamily: "md5",
					QuantumStatus:   types.Broken,
					CryptoFunctions: []string{"digest"},
				},
				Description: "MD5 hash usage (broken)",
				RuleID:      "cbom-python-hashlib-md5",
				Pass:        1,
			},
		},
	}
}

func TestConvertToSARIF_SchemaAndVersion(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	wantSchema := "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	if doc.Schema != wantSchema {
		t.Errorf("Schema = %q, want %q", doc.Schema, wantSchema)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", doc.Version, "2.1.0")
	}
}

func TestConvertToSARIF_SingleRun(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	if len(doc.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(doc.Runs))
	}
}

func TestConvertToSARIF_ToolDriver(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	driver := doc.Runs[0].Tool.Driver
	if driver.Name != "CipherRadar" {
		t.Errorf("driver.Name = %q, want %q", driver.Name, "CipherRadar")
	}
	if driver.Version == "" {
		t.Error("driver.Version should not be empty")
	}
	if driver.InformationURI != "https://github.com/nk-sentinel/cipherradar" {
		t.Errorf("driver.InformationURI = %q, want %q", driver.InformationURI, "https://github.com/nk-sentinel/cipherradar")
	}
}

func TestConvertToSARIF_RulesDeduplication(t *testing.T) {
	// Create a scan result with two findings sharing the same RuleID.
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	result := &types.ScanResult{
		Target:       "/tmp/test",
		StartTime:    now,
		EndTime:      now.Add(time.Second),
		PassesRun:    []int{1},
		FilesScanned: 2,
		Findings: []types.Finding{
			{
				ID:          "FIND-A",
				AssetType:   types.AssetAlgorithm,
				Name:        "AES-128-CBC",
				Location:    types.Location{File: "a.py", StartLine: 1},
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Description: "AES-128 in CBC mode",
				RuleID:      "cbom-python-cipher-aes",
				Pass:        1,
				Properties:  types.CryptoProperties{QuantumStatus: types.QuantumVulnerable},
			},
			{
				ID:          "FIND-B",
				AssetType:   types.AssetAlgorithm,
				Name:        "AES-256-CBC",
				Location:    types.Location{File: "b.py", StartLine: 5},
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Description: "AES-256 in CBC mode",
				RuleID:      "cbom-python-cipher-aes", // same rule
				Pass:        1,
				Properties:  types.CryptoProperties{QuantumStatus: types.QuantumVulnerable},
			},
		},
	}

	doc := ConvertToSARIF(result)
	rules := doc.Runs[0].Tool.Driver.Rules

	if len(rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1 (deduplicated)", len(rules))
	}
	if rules[0].ID != "cbom-python-cipher-aes" {
		t.Errorf("rules[0].ID = %q, want %q", rules[0].ID, "cbom-python-cipher-aes")
	}

	// Both results should reference ruleIndex 0.
	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(results))
	}
	for i, r := range results {
		if r.RuleIndex != 0 {
			t.Errorf("results[%d].RuleIndex = %d, want 0", i, r.RuleIndex)
		}
		if r.RuleID != "cbom-python-cipher-aes" {
			t.Errorf("results[%d].RuleID = %q, want %q", i, r.RuleID, "cbom-python-cipher-aes")
		}
	}
}

func TestConvertToSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity types.Severity
		want     string
	}{
		{types.SeverityCritical, "error"},
		{types.SeverityHigh, "error"},
		{types.SeverityMedium, "warning"},
		{types.SeverityLow, "note"},
		{types.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := severityToSARIFLevel(tt.severity)
			if got != tt.want {
				t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestConvertToSARIF_ResultLevelMapping(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	// Expected levels for the 5 findings in order:
	// medium->warning, low->note, info->note, high->error, critical->error
	expectedLevels := []string{"warning", "note", "note", "error", "error"}
	results := doc.Runs[0].Results

	if len(results) != len(expectedLevels) {
		t.Fatalf("len(Results) = %d, want %d", len(results), len(expectedLevels))
	}

	for i, want := range expectedLevels {
		if results[i].Level != want {
			t.Errorf("results[%d].Level = %q, want %q", i, results[i].Level, want)
		}
	}
}

func TestConvertToSARIF_ResultRuleIDAndIndex(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	results := doc.Runs[0].Results
	rules := doc.Runs[0].Tool.Driver.Rules

	for i, r := range results {
		// ruleId must not be empty.
		if r.RuleID == "" {
			t.Errorf("results[%d].RuleID is empty", i)
		}
		// ruleIndex must be within bounds.
		if r.RuleIndex < 0 || r.RuleIndex >= len(rules) {
			t.Errorf("results[%d].RuleIndex = %d out of bounds [0, %d)", i, r.RuleIndex, len(rules))
		}
		// ruleId must match the rule at ruleIndex.
		if rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("results[%d].RuleID = %q but rules[%d].ID = %q", i, r.RuleID, r.RuleIndex, rules[r.RuleIndex].ID)
		}
	}
}

func TestConvertToSARIF_LocationAndRegion(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	// Check first finding (FIND-001): crypto.py line 7 col 5 to line 7 col 30.
	r := doc.Runs[0].Results[0]
	if len(r.Locations) != 1 {
		t.Fatalf("results[0] len(Locations) = %d, want 1", len(r.Locations))
	}

	pl := r.Locations[0].PhysicalLocation
	if pl.ArtifactLocation.URI != "crypto.py" {
		t.Errorf("artifactLocation.uri = %q, want %q", pl.ArtifactLocation.URI, "crypto.py")
	}
	if pl.Region == nil {
		t.Fatal("region should not be nil")
	}
	if pl.Region.StartLine != 7 {
		t.Errorf("region.startLine = %d, want 7", pl.Region.StartLine)
	}
	if pl.Region.StartColumn != 5 {
		t.Errorf("region.startColumn = %d, want 5", pl.Region.StartColumn)
	}
	if pl.Region.EndLine != 7 {
		t.Errorf("region.endLine = %d, want 7", pl.Region.EndLine)
	}
	if pl.Region.EndColumn != 30 {
		t.Errorf("region.endColumn = %d, want 30", pl.Region.EndColumn)
	}
}

func TestConvertToSARIF_ResultProperties(t *testing.T) {
	result := newSARIFTestScanResult()
	doc := ConvertToSARIF(result)

	// Check first result properties.
	r := doc.Runs[0].Results[0]
	props := r.Properties
	if props == nil {
		t.Fatal("properties should not be nil")
	}

	if v, ok := props["assetType"].(string); !ok || v != "algorithm" {
		t.Errorf("properties.assetType = %v, want %q", props["assetType"], "algorithm")
	}
	if v, ok := props["quantumStatus"].(string); !ok || v != "quantum-vulnerable" {
		t.Errorf("properties.quantumStatus = %v, want %q", props["quantumStatus"], "quantum-vulnerable")
	}
	if v, ok := props["confidence"].(string); !ok || v != "high" {
		t.Errorf("properties.confidence = %v, want %q", props["confidence"], "high")
	}
	if v, ok := props["pass"].(int); !ok || v != 1 {
		t.Errorf("properties.pass = %v, want 1", props["pass"])
	}
}

func TestConvertToSARIF_EmptyScanResult(t *testing.T) {
	result := &types.ScanResult{
		Target:       "/tmp/empty",
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		PassesRun:    []int{1},
		FilesScanned: 0,
	}

	doc := ConvertToSARIF(result)

	if doc.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", doc.Version, "2.1.0")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("len(Results) = %d, want 0", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("len(Rules) = %d, want 0", len(doc.Runs[0].Tool.Driver.Rules))
	}
}

func TestSARIFWriter_ProducesValidJSON(t *testing.T) {
	result := newSARIFTestScanResult()
	w := &SARIFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestSARIFWriter_ContainsSchemaField(t *testing.T) {
	result := newSARIFTestScanResult()
	w := &SARIFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	schema, ok := raw["$schema"].(string)
	if !ok || schema == "" {
		t.Fatal("$schema field missing or empty")
	}
	wantSchema := "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	if schema != wantSchema {
		t.Errorf("$schema = %q, want %q", schema, wantSchema)
	}
}

func TestSARIFWriter_ViaWriterFactory(t *testing.T) {
	w, err := WriterFactory("sarif")
	if err != nil {
		t.Fatalf("WriterFactory(\"sarif\") returned error: %v", err)
	}

	result := newSARIFTestScanResult()
	var buf bytes.Buffer
	err = w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("output is empty")
	}
	// Must contain "$schema".
	if !bytes.Contains(buf.Bytes(), []byte("$schema")) {
		t.Error("output should contain \"$schema\"")
	}
}

func TestSARIFWriter_EndToEnd_RoundTrip(t *testing.T) {
	result := newSARIFTestScanResult()
	w := &SARIFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	// Unmarshal back into a SARIFDocument to verify structure.
	var doc SARIFDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("failed to unmarshal SARIF JSON: %v", err)
	}

	// Validate top-level fields.
	if doc.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", doc.Version, "2.1.0")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(doc.Runs))
	}

	run := doc.Runs[0]

	// Validate tool.
	if run.Tool.Driver.Name != "CipherRadar" {
		t.Errorf("driver.Name = %q, want %q", run.Tool.Driver.Name, "CipherRadar")
	}

	// Validate results count matches findings.
	if len(run.Results) != len(result.Findings) {
		t.Errorf("len(Results) = %d, want %d", len(run.Results), len(result.Findings))
	}

	// Validate rules count (5 findings with 5 unique ruleIDs = 5 rules).
	if len(run.Tool.Driver.Rules) != 5 {
		t.Errorf("len(Rules) = %d, want 5", len(run.Tool.Driver.Rules))
	}

	// Verify each result references a valid rule.
	for i, r := range run.Results {
		if r.RuleID == "" {
			t.Errorf("results[%d].RuleID is empty", i)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("results[%d].RuleIndex = %d out of range", i, r.RuleIndex)
		}
	}

	// Verify severity mappings in the round-tripped data.
	severityMap := map[string]string{
		"FIND-001": "warning", // medium
		"FIND-002": "note",    // low
		"FIND-003": "note",    // info
		"FIND-004": "error",   // high
		"FIND-005": "error",   // critical
	}
	for i, f := range result.Findings {
		expected := severityMap[f.ID]
		if run.Results[i].Level != expected {
			t.Errorf("result for %s: Level = %q, want %q", f.ID, run.Results[i].Level, expected)
		}
	}

	// Verify locations are present.
	for i, r := range run.Results {
		if len(r.Locations) == 0 {
			t.Errorf("results[%d] has no locations", i)
		}
	}

	// Verify properties are present with expected keys.
	expectedKeys := []string{"assetType", "quantumStatus", "confidence", "pass"}
	for i, r := range run.Results {
		if r.Properties == nil {
			t.Errorf("results[%d].Properties is nil", i)
			continue
		}
		for _, key := range expectedKeys {
			if _, ok := r.Properties[key]; !ok {
				t.Errorf("results[%d].Properties missing key %q", i, key)
			}
		}
	}
}
