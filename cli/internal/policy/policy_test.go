package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// testDataDir returns the absolute path to the testdata/policy directory.
func testDataDir(t *testing.T) string {
	t.Helper()
	// Go tests run with cwd set to the package directory.
	// Walk up to find cli/testdata/policy.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	// We're in cli/internal/policy, go up to cli.
	cliDir := filepath.Join(wd, "..", "..")
	return filepath.Join(cliDir, "testdata", "policy")
}

// --- LoadPolicy tests ---

func TestLoadPolicy_SampleFile(t *testing.T) {
	path := filepath.Join(testDataDir(t), "sample-policy.cradar.yml")
	config, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy(%q) returned error: %v", path, err)
	}

	if len(config.Rules) != 6 {
		t.Errorf("expected 6 rules, got %d", len(config.Rules))
	}

	// Verify first rule.
	r := config.Rules[0]
	if r.ID != "no-broken-algorithms" {
		t.Errorf("expected rule ID 'no-broken-algorithms', got %q", r.ID)
	}
	if r.Action != "fail" {
		t.Errorf("expected action 'fail', got %q", r.Action)
	}
	if r.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", r.Severity)
	}
	if len(r.Condition.DenyAlgorithms) != 5 {
		t.Errorf("expected 5 deny_algorithms, got %d", len(r.Condition.DenyAlgorithms))
	}

	// Verify quantum-vulnerable-warning rule is a warn.
	found := false
	for _, rule := range config.Rules {
		if rule.ID == "quantum-vulnerable-warning" {
			found = true
			if rule.Action != "warn" {
				t.Errorf("expected action 'warn' for quantum-vulnerable-warning, got %q", rule.Action)
			}
		}
	}
	if !found {
		t.Error("quantum-vulnerable-warning rule not found")
	}
}

func TestLoadPolicy_NonExistentFile(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.yml")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	// Create a temp file with invalid YAML.
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yml")
	if err := os.WriteFile(path, []byte("{{{{invalid yaml!"), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	_, err := LoadPolicy(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// --- Evaluate tests ---

func makeFinding(name string, algoFamily string, mode string, keySize int, protocolVersion string, quantumStatus types.QuantumStatus, severity types.Severity, file string, line int) types.Finding {
	return types.Finding{
		ID:   "TEST-001",
		Name: name,
		Properties: types.CryptoProperties{
			AlgorithmFamily: algoFamily,
			Mode:            mode,
			KeySize:         keySize,
			ProtocolVersion: protocolVersion,
			QuantumStatus:   quantumStatus,
		},
		Severity: severity,
		Location: types.Location{
			File:      file,
			StartLine: line,
		},
	}
}

func TestEvaluate_DenyAlgorithms_MD5_Fail(t *testing.T) {
	findings := []types.Finding{
		makeFinding("MD5", "md5", "", 0, "", types.Broken, types.SeverityCritical, "auth/crypto.py", 15),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-broken-algorithms",
				Severity: "critical",
				Action:   "fail",
				Condition: Condition{
					DenyAlgorithms: []string{"md5", "sha1", "des", "3des", "rc4"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(report.Violations))
	}
	if report.Violations[0].Result != types.PolicyFail {
		t.Errorf("expected FAIL result, got %s", report.Violations[0].Result)
	}
	if report.Violations[0].RuleID != "no-broken-algorithms" {
		t.Errorf("expected rule ID 'no-broken-algorithms', got %q", report.Violations[0].RuleID)
	}
}

func TestEvaluate_DenyAlgorithms_AES256_NoViolation(t *testing.T) {
	findings := []types.Finding{
		makeFinding("AES-256-GCM", "aes", "gcm", 256, "", types.QuantumSafe, types.SeverityInfo, "crypto/cipher.py", 10),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-broken-algorithms",
				Severity: "critical",
				Action:   "fail",
				Condition: Condition{
					DenyAlgorithms: []string{"md5", "sha1", "des", "3des", "rc4"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations for AES-256, got %d", len(report.Violations))
	}
	if report.Summary.PassCount != 1 {
		t.Errorf("expected 1 pass, got %d", report.Summary.PassCount)
	}
}

func TestEvaluate_DenyModes_ECB_Fail(t *testing.T) {
	findings := []types.Finding{
		makeFinding("AES-ECB", "aes", "ecb", 128, "", types.QuantumSafe, types.SeverityHigh, "crypto/cipher.py", 8),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-ecb-mode",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					DenyModes: []string{"ecb"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(report.Violations))
	}
	if report.Violations[0].Result != types.PolicyFail {
		t.Errorf("expected FAIL, got %s", report.Violations[0].Result)
	}
}

func TestEvaluate_MinKeySize_RSA1024_Fail(t *testing.T) {
	findings := []types.Finding{
		makeFinding("RSA-1024", "rsa", "", 1024, "", types.QuantumVulnerable, types.SeverityHigh, "keys/generate.py", 5),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "rsa-min-key-size",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					Algorithm:  "rsa",
					MinKeySize: 2048,
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 1 {
		t.Fatalf("expected 1 violation for RSA-1024, got %d", len(report.Violations))
	}
	if report.Violations[0].Result != types.PolicyFail {
		t.Errorf("expected FAIL, got %s", report.Violations[0].Result)
	}
}

func TestEvaluate_MinKeySize_RSA2048_Pass(t *testing.T) {
	findings := []types.Finding{
		makeFinding("RSA-2048", "rsa", "", 2048, "", types.QuantumVulnerable, types.SeverityMedium, "keys/generate.py", 5),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "rsa-min-key-size",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					Algorithm:  "rsa",
					MinKeySize: 2048,
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations for RSA-2048, got %d", len(report.Violations))
	}
	if report.Summary.PassCount != 1 {
		t.Errorf("expected 1 pass, got %d", report.Summary.PassCount)
	}
}

func TestEvaluate_DenyTLSVersions_TLS10_Fail(t *testing.T) {
	findings := []types.Finding{
		makeFinding("TLS 1.0", "", "", 0, "1.0", types.QuantumUnknown, types.SeverityHigh, "server/ssl.py", 20),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-deprecated-tls",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					DenyTLSVersions: []string{"1.0", "1.1"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 1 {
		t.Fatalf("expected 1 violation for TLS 1.0, got %d", len(report.Violations))
	}
	if report.Violations[0].Result != types.PolicyFail {
		t.Errorf("expected FAIL, got %s", report.Violations[0].Result)
	}
}

func TestEvaluate_DenyTLSVersions_TLS13_Pass(t *testing.T) {
	findings := []types.Finding{
		makeFinding("TLS 1.3", "", "", 0, "1.3", types.QuantumUnknown, types.SeverityInfo, "server/ssl.py", 20),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-deprecated-tls",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					DenyTLSVersions: []string{"1.0", "1.1"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations for TLS 1.3, got %d", len(report.Violations))
	}
}

func TestEvaluate_DenyQuantumStatus_Vulnerable_Warn(t *testing.T) {
	findings := []types.Finding{
		makeFinding("RSA-2048", "rsa", "", 2048, "", types.QuantumVulnerable, types.SeverityMedium, "keys/generate.py", 5),
	}
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "quantum-vulnerable-warning",
				Severity: "medium",
				Action:   "warn",
				Condition: Condition{
					DenyQuantumStatus: []string{"quantum-vulnerable"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(report.Violations))
	}
	if report.Violations[0].Result != types.PolicyWarn {
		t.Errorf("expected WARN, got %s", report.Violations[0].Result)
	}
}

func TestEvaluate_MultipleRules_CorrectCounts(t *testing.T) {
	findings := []types.Finding{
		makeFinding("MD5", "md5", "", 0, "", types.Broken, types.SeverityCritical, "auth/crypto.py", 15),
		makeFinding("AES-ECB", "aes", "ecb", 128, "", types.QuantumSafe, types.SeverityHigh, "crypto/cipher.py", 8),
		makeFinding("RSA-2048", "rsa", "", 2048, "", types.QuantumVulnerable, types.SeverityMedium, "keys/generate.py", 5),
		makeFinding("AES-256-GCM", "aes", "gcm", 256, "", types.QuantumSafe, types.SeverityInfo, "crypto/cipher.py", 20),
	}

	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-broken-algorithms",
				Severity: "critical",
				Action:   "fail",
				Condition: Condition{
					DenyAlgorithms: []string{"md5", "sha1"},
				},
			},
			{
				ID:       "no-ecb-mode",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					DenyModes: []string{"ecb"},
				},
			},
			{
				ID:       "quantum-vulnerable-warning",
				Severity: "medium",
				Action:   "warn",
				Condition: Condition{
					DenyQuantumStatus: []string{"quantum-vulnerable"},
				},
			},
		},
	}

	report := Evaluate(findings, config)

	// Count violations by type.
	failCount := 0
	warnCount := 0
	for _, v := range report.Violations {
		switch v.Result {
		case types.PolicyFail:
			failCount++
		case types.PolicyWarn:
			warnCount++
		}
	}

	if failCount != 2 {
		t.Errorf("expected 2 FAIL violations, got %d", failCount)
	}
	if warnCount != 1 {
		t.Errorf("expected 1 WARN violation, got %d", warnCount)
	}
	if report.Summary.FailCount != 2 {
		t.Errorf("expected summary FailCount=2, got %d", report.Summary.FailCount)
	}
	if report.Summary.WarnCount != 1 {
		t.Errorf("expected summary WarnCount=1, got %d", report.Summary.WarnCount)
	}
	if report.Summary.PassCount != 0 {
		t.Errorf("expected summary PassCount=0 (all rules had violations), got %d", report.Summary.PassCount)
	}
}

func TestEvaluate_SummaryCountsCorrect(t *testing.T) {
	findings := []types.Finding{
		makeFinding("MD5", "md5", "", 0, "", types.Broken, types.SeverityCritical, "auth/crypto.py", 15),
	}

	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-broken-algorithms",
				Severity: "critical",
				Action:   "fail",
				Condition: Condition{
					DenyAlgorithms: []string{"md5"},
				},
			},
			{
				ID:       "no-ecb-mode",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					DenyModes: []string{"ecb"},
				},
			},
			{
				ID:       "rsa-min-key-size",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					Algorithm:  "rsa",
					MinKeySize: 2048,
				},
			},
		},
	}

	report := Evaluate(findings, config)

	// Only one rule should have violations (no-broken-algorithms).
	if report.Summary.FailCount != 1 {
		t.Errorf("expected FailCount=1, got %d", report.Summary.FailCount)
	}
	if report.Summary.WarnCount != 0 {
		t.Errorf("expected WarnCount=0, got %d", report.Summary.WarnCount)
	}
	if report.Summary.PassCount != 2 {
		t.Errorf("expected PassCount=2, got %d", report.Summary.PassCount)
	}
}

func TestEvaluate_EmptyFindings_NoViolations(t *testing.T) {
	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "no-broken-algorithms",
				Severity: "critical",
				Action:   "fail",
				Condition: Condition{
					DenyAlgorithms: []string{"md5"},
				},
			},
		},
	}

	report := Evaluate([]types.Finding{}, config)

	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations for empty findings, got %d", len(report.Violations))
	}
	if report.Summary.PassCount != 1 {
		t.Errorf("expected PassCount=1 (rule passes with no findings), got %d", report.Summary.PassCount)
	}
}

func TestEvaluate_EmptyRules_NoViolations(t *testing.T) {
	findings := []types.Finding{
		makeFinding("MD5", "md5", "", 0, "", types.Broken, types.SeverityCritical, "auth/crypto.py", 15),
	}

	config := &PolicyConfig{
		Rules: []Rule{},
	}

	report := Evaluate(findings, config)

	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations for empty rules, got %d", len(report.Violations))
	}
}

func TestEvaluate_MinSeverity(t *testing.T) {
	findings := []types.Finding{
		makeFinding("MD5", "md5", "", 0, "", types.Broken, types.SeverityCritical, "auth/crypto.py", 15),
		makeFinding("AES-256-GCM", "aes", "gcm", 256, "", types.QuantumSafe, types.SeverityInfo, "crypto/cipher.py", 20),
	}

	config := &PolicyConfig{
		Rules: []Rule{
			{
				ID:       "high-severity-check",
				Severity: "high",
				Action:   "fail",
				Condition: Condition{
					MinSeverity: "high",
				},
			},
		},
	}

	report := Evaluate(findings, config)

	// Only MD5 (critical, which is >= high) should trigger.
	if len(report.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(report.Violations))
	}
	if report.Violations[0].Finding.Name != "MD5" {
		t.Errorf("expected violation for MD5, got %s", report.Violations[0].Finding.Name)
	}
}

// --- LoadCBOM tests ---

func TestLoadCBOM_ValidFile(t *testing.T) {
	cbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"version": 1,
		"components": [
			{
				"type": "cryptographic-asset",
				"bom-ref": "FIND-001",
				"name": "MD5",
				"description": "MD5 hash function usage",
				"cryptoProperties": {
					"assetType": "algorithm",
					"algorithmProperties": {
						"primitive": "hash",
						"algorithmFamily": "md5"
					}
				},
				"evidence": {
					"occurrences": [
						{
							"location": "auth/crypto.py",
							"line": 15
						}
					]
				}
			}
		]
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test-cbom.json")
	if err := os.WriteFile(path, []byte(cbomJSON), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	findings, err := LoadCBOM(path)
	if err != nil {
		t.Fatalf("LoadCBOM returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FIND-001" {
		t.Errorf("expected ID 'FIND-001', got %q", f.ID)
	}
	if f.Name != "MD5" {
		t.Errorf("expected name 'MD5', got %q", f.Name)
	}
	if f.Properties.AlgorithmFamily != "md5" {
		t.Errorf("expected algorithm family 'md5', got %q", f.Properties.AlgorithmFamily)
	}
	if f.Location.File != "auth/crypto.py" {
		t.Errorf("expected location 'auth/crypto.py', got %q", f.Location.File)
	}
	if f.Location.StartLine != 15 {
		t.Errorf("expected line 15, got %d", f.Location.StartLine)
	}
}

func TestLoadCBOM_NonExistentFile(t *testing.T) {
	_, err := LoadCBOM("/nonexistent/path/cbom.json")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestLoadCBOM_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(path, []byte("{{{invalid json"), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	_, err := LoadCBOM(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
