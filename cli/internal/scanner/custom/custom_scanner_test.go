package custom_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/custom"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ---------------------------------------------------------------------------
// Interface tests
// ---------------------------------------------------------------------------

func TestCustomScannerName(t *testing.T) {
	s := custom.New([]config.CustomWrapper{
		{Name: "test.encrypt", Language: "python", Type: "algorithm"},
	})
	if s.Name() != "custom" {
		t.Errorf("expected Name() = %q, got %q", "custom", s.Name())
	}
}

func TestCustomScanner_NilWithEmptyWrappers(t *testing.T) {
	s := custom.New(nil)
	if s != nil {
		t.Error("expected nil scanner for empty wrappers")
	}

	s = custom.New([]config.CustomWrapper{})
	if s != nil {
		t.Error("expected nil scanner for empty slice")
	}
}

// ---------------------------------------------------------------------------
// Python wrapper detection
// ---------------------------------------------------------------------------

func TestCustomScanner_DetectsPythonWrapper(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{
			Name:     "mycompany.crypto.encrypt",
			Language: "python",
			Type:     "algorithm",
			Parameters: map[string]int{
				"key":       0,
				"algorithm": 1,
			},
			Severity: "info",
		},
	}

	s := custom.New(wrappers)

	content := []byte(`from mycompany.crypto import encrypt

result = mycompany.crypto.encrypt(key, "AES-256-GCM")
print(result)
`)

	findings, err := s.ScanFile("app.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for custom wrapper call")
	}

	found := false
	for _, f := range findings {
		if f.Name == "mycompany.crypto.encrypt" && f.AssetType == types.AssetAlgorithm {
			found = true
			if f.Severity != types.SeverityInfo {
				t.Errorf("expected severity info, got %s", f.Severity)
			}
			if f.Location.File != "app.py" {
				t.Errorf("expected file app.py, got %s", f.Location.File)
			}
			if f.Pass != 1 {
				t.Errorf("expected pass 1, got %d", f.Pass)
			}
		}
	}
	if !found {
		t.Error("expected to find mycompany.crypto.encrypt finding")
	}
}

// ---------------------------------------------------------------------------
// Java wrapper detection
// ---------------------------------------------------------------------------

func TestCustomScanner_DetectsJavaWrapper(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{
			Name:     "com.myco.CryptoUtil.encrypt",
			Language: "java",
			Type:     "algorithm",
			Parameters: map[string]int{
				"key":       1,
				"algorithm": 0,
			},
			Severity: "medium",
		},
	}

	s := custom.New(wrappers)

	content := []byte(`package com.myco.app;

import com.myco.CryptoUtil;

public class Main {
    public static void main(String[] args) {
        byte[] result = CryptoUtil.encrypt("AES", secretKey);
    }
}
`)

	findings, err := s.ScanFile("Main.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for Java wrapper call")
	}

	found := false
	for _, f := range findings {
		if f.Name == "com.myco.CryptoUtil.encrypt" {
			found = true
			if f.Severity != types.SeverityMedium {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected to find com.myco.CryptoUtil.encrypt finding")
	}
}

// ---------------------------------------------------------------------------
// Language filtering
// ---------------------------------------------------------------------------

func TestCustomScanner_IgnoresWrongLanguage(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{
			Name:     "mylib.encrypt",
			Language: "java",
			Type:     "algorithm",
			Severity: "info",
		},
	}

	s := custom.New(wrappers)

	// Python file should not match a Java-only wrapper.
	content := []byte(`result = mylib.encrypt(data)
`)

	findings, err := s.ScanFile("script.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for wrong language, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Empty content
// ---------------------------------------------------------------------------

func TestCustomScanner_EmptyContent(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{Name: "test.encrypt", Language: "python", Type: "algorithm", Severity: "info"},
	}

	s := custom.New(wrappers)
	findings, err := s.ScanFile("empty.py", []byte{})
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty content, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Multiple wrappers
// ---------------------------------------------------------------------------

func TestCustomScanner_MultipleWrappers(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{Name: "crypto.encrypt", Language: "python", Type: "algorithm", Severity: "info"},
		{Name: "crypto.sign", Language: "python", Type: "algorithm", Severity: "high"},
	}

	s := custom.New(wrappers)

	content := []byte(`crypto.encrypt(data, key)
crypto.sign(payload, private_key)
`)

	findings, err := s.ScanFile("app.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	foundEncrypt := false
	foundSign := false
	for _, f := range findings {
		if f.Name == "crypto.encrypt" {
			foundEncrypt = true
		}
		if f.Name == "crypto.sign" {
			foundSign = true
		}
	}

	if !foundEncrypt {
		t.Error("expected to find crypto.encrypt")
	}
	if !foundSign {
		t.Error("expected to find crypto.sign")
	}
}

// ---------------------------------------------------------------------------
// Asset type mapping
// ---------------------------------------------------------------------------

func TestCustomScanner_AssetTypeMapping(t *testing.T) {
	tests := []struct {
		wrapperType string
		want        types.AssetType
	}{
		{"algorithm", types.AssetAlgorithm},
		{"protocol", types.AssetProtocol},
		{"certificate", types.AssetCertificate},
		{"related-crypto-material", types.AssetRelatedCryptoMaterial},
		{"unknown", types.AssetAlgorithm}, // default
	}

	for _, tt := range tests {
		t.Run(tt.wrapperType, func(t *testing.T) {
			s := custom.New([]config.CustomWrapper{
				{Name: "test.func", Language: "python", Type: tt.wrapperType, Severity: "info"},
			})

			content := []byte(`test.func(arg)
`)
			findings, err := s.ScanFile("test.py", content)
			if err != nil {
				t.Fatalf("ScanFile failed: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if findings[0].AssetType != tt.want {
				t.Errorf("AssetType = %q, want %q", findings[0].AssetType, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

func TestCustomScanner_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		want     types.Severity
	}{
		{"critical", types.SeverityCritical},
		{"high", types.SeverityHigh},
		{"medium", types.SeverityMedium},
		{"low", types.SeverityLow},
		{"info", types.SeverityInfo},
		{"", types.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			s := custom.New([]config.CustomWrapper{
				{Name: "test.func", Language: "python", Type: "algorithm", Severity: tt.severity},
			})

			content := []byte(`test.func(arg)
`)
			findings, err := s.ScanFile("test.py", content)
			if err != nil {
				t.Fatalf("ScanFile failed: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if findings[0].Severity != tt.want {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Short name matching (last component after dot)
// ---------------------------------------------------------------------------

func TestCustomScanner_ShortNameMatching(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{Name: "com.company.SecurityHelper.encrypt", Language: "java", Type: "algorithm", Severity: "info"},
	}

	s := custom.New(wrappers)

	// In Java code, the developer might call just `encrypt(...)` after importing.
	content := []byte(`byte[] result = encrypt(data, key);
`)

	findings, err := s.ScanFile("Test.java", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected to find wrapper via short name matching")
	}
}

// ---------------------------------------------------------------------------
// ScanFileForLanguage
// ---------------------------------------------------------------------------

func TestCustomScanner_ScanFileForLanguage(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{Name: "crypto.encrypt", Language: "python", Type: "algorithm", Severity: "info"},
		{Name: "crypto.encrypt", Language: "java", Type: "algorithm", Severity: "high"},
	}

	s := custom.New(wrappers)

	content := []byte(`crypto.encrypt(data)
`)

	// Request Python language explicitly.
	findings, err := s.ScanFileForLanguage("unknown.txt", content, "python")
	if err != nil {
		t.Fatalf("ScanFileForLanguage failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Should have info severity (Python wrapper), not high (Java wrapper).
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("expected info severity, got %s", findings[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// Finding fields
// ---------------------------------------------------------------------------

func TestCustomScanner_FindingFields(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{Name: "mylib.hash", Language: "python", Type: "algorithm", Severity: "low"},
	}

	s := custom.New(wrappers)

	content := []byte(`x = 1
digest = mylib.hash(data)
y = 2
`)

	findings, err := s.ScanFile("app.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := findings[0]
	if f.ID == "" {
		t.Error("finding ID should not be empty")
	}
	if f.RuleID == "" {
		t.Error("finding RuleID should not be empty")
	}
	if f.Location.StartLine != 2 {
		t.Errorf("expected StartLine 2, got %d", f.Location.StartLine)
	}
	if f.Description == "" {
		t.Error("Description should not be empty")
	}
	if f.Confidence != types.ConfidenceMedium {
		t.Errorf("expected confidence medium, got %s", f.Confidence)
	}
}

// ---------------------------------------------------------------------------
// No matches when wrapper not called
// ---------------------------------------------------------------------------

func TestCustomScanner_NoMatchWhenNotCalled(t *testing.T) {
	wrappers := []config.CustomWrapper{
		{Name: "crypto.encrypt", Language: "python", Type: "algorithm", Severity: "info"},
	}

	s := custom.New(wrappers)

	content := []byte(`# This file does not call any crypto wrappers
x = 42
print(x)
`)

	findings, err := s.ScanFile("safe.py", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
