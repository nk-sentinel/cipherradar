package joern

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// sampleJoernJSON is a realistic Joern JSON output for testing.
const sampleJoernJSON = `{
  "findings": [
    {
      "name": "hardcoded-aes-key",
      "file": "crypto/encryption.py",
      "line": 15,
      "endLine": 15,
      "column": 5,
      "endColumn": 40,
      "code": "key = b'hardcoded-secret-key-1234'",
      "severity": "high",
      "flow": [
        { "file": "crypto/encryption.py", "line": 15, "code": "key = b'hardcoded'" },
        { "file": "crypto/encryption.py", "line": 22, "code": "cipher = AES.new(key)" }
      ]
    },
    {
      "name": "weak-rsa-key",
      "file": "auth/keys.py",
      "line": 42,
      "endLine": 42,
      "column": 1,
      "endColumn": 50,
      "code": "rsa_key = RSA.generate(1024)",
      "severity": "critical",
      "flow": []
    },
    {
      "name": "tls-downgrade",
      "file": "net/client.py",
      "line": 8,
      "endLine": 8,
      "column": 10,
      "endColumn": 55,
      "code": "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
      "severity": "medium",
      "flow": [
        { "file": "net/client.py", "line": 8, "code": "ctx = ssl.SSLContext()" },
        { "file": "net/client.py", "line": 15, "code": "conn = ctx.wrap_socket(sock)" }
      ]
    }
  ]
}`

func TestParseResultsValidJSON(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-test-query")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestParseResultsPass3(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-test-query")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, f := range findings {
		if f.Pass != 3 {
			t.Errorf("finding[%d]: expected Pass=3, got Pass=%d", i, f.Pass)
		}
	}
}

func TestParseResultsRuleID(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-crypto-key-flow")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, f := range findings {
		if f.RuleID != "joern-crypto-key-flow" {
			t.Errorf("finding[%d]: expected RuleID=%q, got %q", i, "joern-crypto-key-flow", f.RuleID)
		}
	}
}

func TestParseResultsSeverityMapping(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedSev := []types.Severity{
		types.SeverityHigh,     // "high" -> High
		types.SeverityCritical, // "critical" -> Critical
		types.SeverityMedium,   // "medium" -> Medium
	}

	for i, f := range findings {
		if f.Severity != expectedSev[i] {
			t.Errorf("finding[%d]: expected Severity=%q, got %q", i, expectedSev[i], f.Severity)
		}
	}
}

func TestParseResultsLocationMapping(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check the first finding's location.
	f := findings[0]
	if f.Location.File != "crypto/encryption.py" {
		t.Errorf("expected file=crypto/encryption.py, got %q", f.Location.File)
	}
	if f.Location.StartLine != 15 {
		t.Errorf("expected StartLine=15, got %d", f.Location.StartLine)
	}
	if f.Location.StartCol != 5 {
		t.Errorf("expected StartCol=5, got %d", f.Location.StartCol)
	}
	if f.Location.EndLine != 15 {
		t.Errorf("expected EndLine=15, got %d", f.Location.EndLine)
	}
	if f.Location.EndCol != 40 {
		t.Errorf("expected EndCol=40, got %d", f.Location.EndCol)
	}
	if f.Location.Snippet != "key = b'hardcoded-secret-key-1234'" {
		t.Errorf("expected snippet=%q, got %q", "key = b'hardcoded-secret-key-1234'", f.Location.Snippet)
	}
}

func TestParseResultsFlowDescription(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First finding has a flow with 2 hops.
	expected := "hardcoded-aes-key [flow: crypto/encryption.py:15 -> crypto/encryption.py:22]"
	if findings[0].Description != expected {
		t.Errorf("unexpected description: got %q, want %q", findings[0].Description, expected)
	}

	// Second finding has empty flow — description should be just the name.
	if findings[1].Description != "weak-rsa-key" {
		t.Errorf("unexpected description for no-flow finding: %q", findings[1].Description)
	}
}

func TestParseResultsAssetTypeInference(t *testing.T) {
	findings, err := ParseResults([]byte(sampleJoernJSON), "joern-crypto-key-flow")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// "hardcoded-aes-key" + rule with "key" -> related-crypto-material
	if findings[0].AssetType != types.AssetRelatedCryptoMaterial {
		t.Errorf("finding[0]: expected AssetType=%q, got %q", types.AssetRelatedCryptoMaterial, findings[0].AssetType)
	}

	// "weak-rsa-key" + rule with "key" -> related-crypto-material
	if findings[1].AssetType != types.AssetRelatedCryptoMaterial {
		t.Errorf("finding[1]: expected AssetType=%q, got %q", types.AssetRelatedCryptoMaterial, findings[1].AssetType)
	}

	// "tls-downgrade" -> protocol
	if findings[2].AssetType != types.AssetProtocol {
		t.Errorf("finding[2]: expected AssetType=%q, got %q", types.AssetProtocol, findings[2].AssetType)
	}
}

func TestParseResultsEmptyResults(t *testing.T) {
	emptyJSON := `{"findings": []}`
	findings, err := ParseResults([]byte(emptyJSON), "joern-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseResultsEmptyInput(t *testing.T) {
	findings, err := ParseResults([]byte{}, "joern-test")
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}
}

func TestParseResultsMalformedJSON(t *testing.T) {
	malformed := `{"findings": [{"name": "broken`
	_, err := ParseResults([]byte(malformed), "joern-test")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestParseResultsNotJSON(t *testing.T) {
	_, err := ParseResults([]byte("this is not json"), "joern-test")
	if err == nil {
		t.Error("expected error for non-JSON input")
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected types.Severity
	}{
		{"critical", types.SeverityCritical},
		{"CRITICAL", types.SeverityCritical},
		{"high", types.SeverityHigh},
		{"HIGH", types.SeverityHigh},
		{"medium", types.SeverityMedium},
		{"warning", types.SeverityMedium},
		{"low", types.SeverityLow},
		{"info", types.SeverityInfo},
		{"UNKNOWN", types.SeverityMedium},
		{"", types.SeverityMedium},
	}

	for _, tc := range tests {
		got := mapSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("mapSeverity(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestInferAssetType(t *testing.T) {
	tests := []struct {
		ruleID   string
		name     string
		expected types.AssetType
	}{
		{"joern-crypto-key-flow", "hardcoded-key", types.AssetRelatedCryptoMaterial},
		{"joern-secret-flow", "api-secret", types.AssetRelatedCryptoMaterial},
		{"joern-tls-check", "tls-downgrade", types.AssetProtocol},
		{"joern-ssl-verify", "ssl-check", types.AssetProtocol},
		{"joern-cert-check", "certificate-validation", types.AssetCertificate},
		{"joern-weak-algo", "md5-usage", types.AssetAlgorithm},
		{"joern-misc", "unknown-thing", types.AssetAlgorithm},
	}

	for _, tc := range tests {
		got := inferAssetType(tc.ruleID, tc.name)
		if got != tc.expected {
			t.Errorf("inferAssetType(%q, %q) = %q, want %q", tc.ruleID, tc.name, got, tc.expected)
		}
	}
}
