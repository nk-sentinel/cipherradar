package opengrep

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// sampleOpenGrepJSON is a realistic OpenGrep/Semgrep JSON output for testing.
const sampleOpenGrepJSON = `{
  "results": [
    {
      "check_id": "cbom-python-hardcoded-key",
      "path": "crypto/encryption.py",
      "start": { "line": 15, "col": 5 },
      "end": { "line": 15, "col": 40 },
      "extra": {
        "message": "Hardcoded key detected flowing into cipher initialization",
        "severity": "WARNING",
        "metadata": {
          "cbom-asset-type": "related-crypto-material",
          "confidence": "high",
          "quantum-relevant": false
        },
        "lines": "key = b'hardcoded-secret-key-1234'"
      }
    },
    {
      "check_id": "cbom-python-weak-hash",
      "path": "utils/hashing.py",
      "start": { "line": 42, "col": 1 },
      "end": { "line": 42, "col": 30 },
      "extra": {
        "message": "Use of MD5 hash detected",
        "severity": "ERROR",
        "metadata": {
          "cbom-asset-type": "algorithm",
          "confidence": "medium",
          "quantum-relevant": false
        },
        "lines": "digest = hashlib.md5(data)"
      }
    },
    {
      "check_id": "cbom-java-tls-version",
      "path": "src/main/java/TlsConfig.java",
      "start": { "line": 8, "col": 10 },
      "end": { "line": 8, "col": 50 },
      "extra": {
        "message": "TLS 1.0 protocol usage detected",
        "severity": "INFO",
        "metadata": {
          "cbom-asset-type": "protocol",
          "confidence": "low",
          "quantum-relevant": false
        },
        "lines": "SSLContext ctx = SSLContext.getInstance(\"TLSv1\");"
      }
    }
  ],
  "errors": []
}`

func TestParseResultsValidJSON(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestParseResultsPass2(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, f := range findings {
		if f.Pass != 2 {
			t.Errorf("finding[%d]: expected Pass=2, got Pass=%d", i, f.Pass)
		}
	}
}

func TestParseResultsRuleID(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"cbom-python-hardcoded-key",
		"cbom-python-weak-hash",
		"cbom-java-tls-version",
	}

	for i, f := range findings {
		if f.RuleID != expected[i] {
			t.Errorf("finding[%d]: expected RuleID=%q, got %q", i, expected[i], f.RuleID)
		}
	}
}

func TestParseResultsSeverityMapping(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedSev := []types.Severity{
		types.SeverityMedium, // WARNING -> Medium
		types.SeverityHigh,   // ERROR -> High
		types.SeverityInfo,   // INFO -> Info
	}

	for i, f := range findings {
		if f.Severity != expectedSev[i] {
			t.Errorf("finding[%d]: expected Severity=%q, got %q", i, expectedSev[i], f.Severity)
		}
	}
}

func TestParseResultsLocationMapping(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
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

func TestParseResultsMetadataExtraction(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First finding: related-crypto-material, high confidence.
	if findings[0].AssetType != types.AssetRelatedCryptoMaterial {
		t.Errorf("finding[0]: expected AssetType=%q, got %q", types.AssetRelatedCryptoMaterial, findings[0].AssetType)
	}
	if findings[0].Confidence != types.ConfidenceHigh {
		t.Errorf("finding[0]: expected Confidence=%q, got %q", types.ConfidenceHigh, findings[0].Confidence)
	}

	// Second finding: algorithm, medium confidence.
	if findings[1].AssetType != types.AssetAlgorithm {
		t.Errorf("finding[1]: expected AssetType=%q, got %q", types.AssetAlgorithm, findings[1].AssetType)
	}
	if findings[1].Confidence != types.ConfidenceMedium {
		t.Errorf("finding[1]: expected Confidence=%q, got %q", types.ConfidenceMedium, findings[1].Confidence)
	}

	// Third finding: protocol, low confidence.
	if findings[2].AssetType != types.AssetProtocol {
		t.Errorf("finding[2]: expected AssetType=%q, got %q", types.AssetProtocol, findings[2].AssetType)
	}
	if findings[2].Confidence != types.ConfidenceLow {
		t.Errorf("finding[2]: expected Confidence=%q, got %q", types.ConfidenceLow, findings[2].Confidence)
	}
}

func TestParseResultsDescription(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findings[0].Description != "Hardcoded key detected flowing into cipher initialization" {
		t.Errorf("unexpected description: %q", findings[0].Description)
	}
}

func TestParseResultsNameDerivedFromCheckID(t *testing.T) {
	findings, err := ParseResults([]byte(sampleOpenGrepJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedNames := []string{
		"hardcoded-key", // "cbom-python-hardcoded-key" -> "hardcoded-key"
		"weak-hash",     // "cbom-python-weak-hash" -> "weak-hash"
		"tls-version",   // "cbom-java-tls-version" -> "tls-version"
	}

	for i, f := range findings {
		if f.Name != expectedNames[i] {
			t.Errorf("finding[%d]: expected Name=%q, got %q", i, expectedNames[i], f.Name)
		}
	}
}

func TestParseResultsEmptyResults(t *testing.T) {
	emptyJSON := `{"results": [], "errors": []}`
	findings, err := ParseResults([]byte(emptyJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseResultsEmptyInput(t *testing.T) {
	findings, err := ParseResults([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}
}

func TestParseResultsMalformedJSON(t *testing.T) {
	malformed := `{"results": [{"check_id": "broken`
	_, err := ParseResults([]byte(malformed))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestParseResultsNotJSON(t *testing.T) {
	_, err := ParseResults([]byte("this is not json"))
	if err == nil {
		t.Error("expected error for non-JSON input")
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected types.Severity
	}{
		{"ERROR", types.SeverityHigh},
		{"error", types.SeverityHigh},
		{"WARNING", types.SeverityMedium},
		{"warning", types.SeverityMedium},
		{"INFO", types.SeverityInfo},
		{"info", types.SeverityInfo},
		{"UNKNOWN", types.SeverityInfo},
		{"", types.SeverityInfo},
	}

	for _, tc := range tests {
		got := mapSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("mapSeverity(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestMapConfidence(t *testing.T) {
	tests := []struct {
		input    string
		expected types.Confidence
	}{
		{"high", types.ConfidenceHigh},
		{"HIGH", types.ConfidenceHigh},
		{"medium", types.ConfidenceMedium},
		{"low", types.ConfidenceLow},
		{"", types.ConfidenceMedium},
		{"unknown", types.ConfidenceMedium},
	}

	for _, tc := range tests {
		got := mapConfidence(tc.input)
		if got != tc.expected {
			t.Errorf("mapConfidence(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestMapAssetType(t *testing.T) {
	tests := []struct {
		input    string
		expected types.AssetType
	}{
		{"algorithm", types.AssetAlgorithm},
		{"protocol", types.AssetProtocol},
		{"certificate", types.AssetCertificate},
		{"related-crypto-material", types.AssetRelatedCryptoMaterial},
		{"", types.AssetAlgorithm},
		{"custom-type", types.AssetType("custom-type")},
	}

	for _, tc := range tests {
		got := mapAssetType(tc.input)
		if got != tc.expected {
			t.Errorf("mapAssetType(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// sampleLifecycleJSON exercises the lifecycle metadata fields: category,
// maturity, default_enabled, noise_risk. Three results cover:
//   - full lifecycle metadata set (inventory, stable, low, true)
//   - experimental + noisy + default-off
//   - metadata fully absent (exercises forward-compat defaults)
const sampleLifecycleJSON = `{
  "results": [
    {
      "check_id": "cbom-python-rsa-inventory",
      "path": "app/crypto.py",
      "start": {"line": 1, "col": 1},
      "end": {"line": 1, "col": 10},
      "extra": {
        "message": "RSA key generation",
        "severity": "INFO",
        "metadata": {
          "cbom-asset-type": "algorithm",
          "category": "inventory",
          "maturity": "stable",
          "default_enabled": true,
          "noise_risk": "low"
        }
      }
    },
    {
      "check_id": "cbom-python-hardcoded-key-cipher",
      "path": "app/secrets.py",
      "start": {"line": 5, "col": 1},
      "end": {"line": 5, "col": 20},
      "extra": {
        "message": "Hardcoded key",
        "severity": "WARNING",
        "metadata": {
          "cbom-asset-type": "related-crypto-material",
          "category": "security",
          "maturity": "experimental",
          "default_enabled": false,
          "noise_risk": "high"
        }
      }
    },
    {
      "check_id": "cbom-legacy-rule-no-lifecycle",
      "path": "legacy/old.py",
      "start": {"line": 1, "col": 1},
      "end": {"line": 1, "col": 5},
      "extra": {
        "message": "Legacy rule missing lifecycle metadata",
        "severity": "INFO",
        "metadata": {
          "cbom-asset-type": "algorithm"
        }
      }
    }
  ],
  "errors": []
}`

func TestParseResultsLifecycleMetadata(t *testing.T) {
	findings, err := ParseResults([]byte(sampleLifecycleJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Result 0: full lifecycle metadata, inventory/stable/low/enabled.
	if findings[0].Category != types.CategoryInventory {
		t.Errorf("findings[0].Category = %q, want %q", findings[0].Category, types.CategoryInventory)
	}
	if findings[0].Maturity != types.MaturityStable {
		t.Errorf("findings[0].Maturity = %q, want %q", findings[0].Maturity, types.MaturityStable)
	}
	if findings[0].NoiseRisk != types.NoiseRiskLow {
		t.Errorf("findings[0].NoiseRisk = %q, want %q", findings[0].NoiseRisk, types.NoiseRiskLow)
	}
	if !findings[0].DefaultEnabled {
		t.Errorf("findings[0].DefaultEnabled = false, want true")
	}

	// Result 1: experimental / noisy / default-off.
	if findings[1].Category != types.CategorySecurity {
		t.Errorf("findings[1].Category = %q, want %q", findings[1].Category, types.CategorySecurity)
	}
	if findings[1].Maturity != types.MaturityExperimental {
		t.Errorf("findings[1].Maturity = %q, want %q", findings[1].Maturity, types.MaturityExperimental)
	}
	if findings[1].NoiseRisk != types.NoiseRiskHigh {
		t.Errorf("findings[1].NoiseRisk = %q, want %q", findings[1].NoiseRisk, types.NoiseRiskHigh)
	}
	if findings[1].DefaultEnabled {
		t.Errorf("findings[1].DefaultEnabled = true, want false")
	}

	// Result 2: lifecycle metadata absent — defaults should apply.
	// Unset category → security (conservative).
	// Unset maturity → stable (forward-compat).
	// Unset noise_risk → low.
	// Unset default_enabled → true (forward-compat).
	if findings[2].Category != types.CategorySecurity {
		t.Errorf("findings[2].Category (default) = %q, want %q", findings[2].Category, types.CategorySecurity)
	}
	if findings[2].Maturity != types.MaturityStable {
		t.Errorf("findings[2].Maturity (default) = %q, want %q", findings[2].Maturity, types.MaturityStable)
	}
	if findings[2].NoiseRisk != types.NoiseRiskLow {
		t.Errorf("findings[2].NoiseRisk (default) = %q, want %q", findings[2].NoiseRisk, types.NoiseRiskLow)
	}
	if !findings[2].DefaultEnabled {
		t.Errorf("findings[2].DefaultEnabled (default) = false, want true")
	}
}

func TestMapCategory(t *testing.T) {
	tests := []struct {
		input string
		want  types.Category
	}{
		{"inventory", types.CategoryInventory},
		{"INVENTORY", types.CategoryInventory},
		{" inventory ", types.CategoryInventory},
		{"security", types.CategorySecurity},
		{"", types.CategorySecurity},
		{"bogus", types.CategorySecurity},
	}
	for _, tc := range tests {
		if got := mapCategory(tc.input); got != tc.want {
			t.Errorf("mapCategory(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestMapMaturity(t *testing.T) {
	tests := []struct {
		input string
		want  types.Maturity
	}{
		{"experimental", types.MaturityExperimental},
		{"stable", types.MaturityStable},
		{"deprecated", types.MaturityDeprecated},
		{"", types.MaturityStable},
		{"bogus", types.MaturityStable},
	}
	for _, tc := range tests {
		if got := mapMaturity(tc.input); got != tc.want {
			t.Errorf("mapMaturity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestMapNoiseRisk(t *testing.T) {
	tests := []struct {
		input string
		want  types.NoiseRisk
	}{
		{"low", types.NoiseRiskLow},
		{"med", types.NoiseRiskMedium},
		{"medium", types.NoiseRiskMedium},
		{"high", types.NoiseRiskHigh},
		{"", types.NoiseRiskLow},
		{"bogus", types.NoiseRiskLow},
	}
	for _, tc := range tests {
		if got := mapNoiseRisk(tc.input); got != tc.want {
			t.Errorf("mapNoiseRisk(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestMapDefaultEnabled(t *testing.T) {
	tr, fl := true, false
	tests := []struct {
		input *bool
		want  bool
	}{
		{nil, true}, // unset → default true (forward-compat)
		{&tr, true},
		{&fl, false},
	}
	for i, tc := range tests {
		if got := mapDefaultEnabled(tc.input); got != tc.want {
			t.Errorf("case %d: mapDefaultEnabled() = %v, want %v", i, got, tc.want)
		}
	}
}

func TestDeriveNameFromCheckID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"cbom-python-hardcoded-key", "hardcoded-key"},
		{"cbom-java-weak-cipher", "weak-cipher"},
		{"cbom-javascript-insecure-random", "insecure-random"},
		{"cbom-js-crypto-import", "crypto-import"},
		{"cbom-generic-rule", "generic-rule"},
		{"custom-rule-id", "custom-rule-id"},
		{"", ""},
	}

	for _, tc := range tests {
		got := deriveNameFromCheckID(tc.input)
		if got != tc.expected {
			t.Errorf("deriveNameFromCheckID(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
