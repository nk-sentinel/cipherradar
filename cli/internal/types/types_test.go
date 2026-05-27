package types

import (
	"testing"
	"time"
)

func TestAssetTypeEnumValues(t *testing.T) {
	tests := []struct {
		got  AssetType
		want string
	}{
		{AssetAlgorithm, "algorithm"},
		{AssetProtocol, "protocol"},
		{AssetCertificate, "certificate"},
		{AssetRelatedCryptoMaterial, "related-crypto-material"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("AssetType = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestSeverityEnumValues(t *testing.T) {
	tests := []struct {
		got  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("Severity = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestConfidenceEnumValues(t *testing.T) {
	tests := []struct {
		got  Confidence
		want string
	}{
		{ConfidenceHigh, "high"},
		{ConfidenceMedium, "medium"},
		{ConfidenceLow, "low"},
		{ConfidenceUnresolved, "unresolved"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("Confidence = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestQuantumStatusEnumValues(t *testing.T) {
	tests := []struct {
		got  QuantumStatus
		want string
	}{
		{QuantumVulnerable, "quantum-vulnerable"},
		{QuantumSafe, "quantum-safe"},
		{QuantumUnknown, "quantum-unknown"},
		{Broken, "broken"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("QuantumStatus = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestPolicyResultEnumValues(t *testing.T) {
	tests := []struct {
		got  PolicyResult
		want string
	}{
		{PolicyPass, "pass"},
		{PolicyFail, "fail"},
		{PolicyWarn, "warn"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("PolicyResult = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestFindingFullyPopulated(t *testing.T) {
	f := Finding{
		ID:        "FIND-001",
		AssetType: AssetAlgorithm,
		Name:      "AES-256-CBC",
		Location: Location{
			File:      "crypto/aes.py",
			StartLine: 42,
			StartCol:  5,
			EndLine:   42,
			EndCol:    30,
			Snippet:   `cipher = AES.new(key, AES.MODE_CBC)`,
		},
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Properties: CryptoProperties{
			Primitive:         "block-cipher",
			AlgorithmFamily:   "aes",
			Mode:              "cbc",
			Padding:           "pkcs7",
			KeySize:           256,
			ClassicalSecurity: 256,
			NistQuantumLevel:  1,
			QuantumStatus:     QuantumVulnerable,
			CryptoFunctions:   []string{"encrypt", "decrypt"},
		},
		Description: "AES-256 in CBC mode detected",
		RuleID:      "cbom-python-aes-cbc",
		Pass:        1,
	}

	if f.ID != "FIND-001" {
		t.Errorf("Finding.ID = %q, want %q", f.ID, "FIND-001")
	}
	if f.AssetType != AssetAlgorithm {
		t.Errorf("Finding.AssetType = %q, want %q", f.AssetType, AssetAlgorithm)
	}
	if f.Location.File != "crypto/aes.py" {
		t.Errorf("Finding.Location.File = %q, want %q", f.Location.File, "crypto/aes.py")
	}
	if f.Properties.KeySize != 256 {
		t.Errorf("Finding.Properties.KeySize = %d, want %d", f.Properties.KeySize, 256)
	}
	if len(f.Properties.CryptoFunctions) != 2 {
		t.Errorf("Finding.Properties.CryptoFunctions length = %d, want %d", len(f.Properties.CryptoFunctions), 2)
	}
	if f.Pass != 1 {
		t.Errorf("Finding.Pass = %d, want %d", f.Pass, 1)
	}
}

func TestScanResultFindingsAppend(t *testing.T) {
	result := ScanResult{
		Target:    "/project",
		StartTime: time.Now(),
		PassesRun: []int{1, 2},
	}

	f1 := Finding{ID: "FIND-001", Name: "AES-256-CBC", AssetType: AssetAlgorithm}
	f2 := Finding{ID: "FIND-002", Name: "TLS 1.2", AssetType: AssetProtocol}
	f3 := Finding{ID: "FIND-003", Name: "RSA-2048", AssetType: AssetRelatedCryptoMaterial}

	result.Findings = append(result.Findings, f1, f2, f3)

	if len(result.Findings) != 3 {
		t.Errorf("ScanResult.Findings length = %d, want %d", len(result.Findings), 3)
	}
	if result.Findings[0].ID != "FIND-001" {
		t.Errorf("ScanResult.Findings[0].ID = %q, want %q", result.Findings[0].ID, "FIND-001")
	}
	if result.Findings[1].AssetType != AssetProtocol {
		t.Errorf("ScanResult.Findings[1].AssetType = %q, want %q", result.Findings[1].AssetType, AssetProtocol)
	}
	if result.Findings[2].AssetType != AssetRelatedCryptoMaterial {
		t.Errorf("ScanResult.Findings[2].AssetType = %q, want %q", result.Findings[2].AssetType, AssetRelatedCryptoMaterial)
	}
}

func TestQuantumNotApplicable(t *testing.T) {
	if QuantumNotApplicable != "not-applicable" {
		t.Errorf("QuantumNotApplicable = %q, want not-applicable", QuantumNotApplicable)
	}
}

func TestScanResultTimestamps(t *testing.T) {
	start := time.Now()
	result := ScanResult{
		Target:    "/project",
		StartTime: start,
		EndTime:   start.Add(5 * time.Second),
	}

	duration := result.EndTime.Sub(result.StartTime)
	if duration != 5*time.Second {
		t.Errorf("Scan duration = %v, want %v", duration, 5*time.Second)
	}
}

func TestScanErrorFields(t *testing.T) {
	scanErr := ScanError{
		File:    "broken.py",
		Message: "syntax error on line 10",
		Err:     nil,
	}

	if scanErr.File != "broken.py" {
		t.Errorf("ScanError.File = %q, want %q", scanErr.File, "broken.py")
	}
	if scanErr.Message != "syntax error on line 10" {
		t.Errorf("ScanError.Message = %q, want %q", scanErr.Message, "syntax error on line 10")
	}
}

func TestPolicyReportStructure(t *testing.T) {
	report := PolicyReport{
		Violations: []PolicyViolation{
			{
				RuleID:      "no-md5",
				Description: "MD5 is not allowed",
				Finding:     Finding{ID: "FIND-010", Name: "MD5", AssetType: AssetAlgorithm},
				Result:      PolicyFail,
				Severity:    SeverityHigh,
			},
			{
				RuleID:      "prefer-aes-256",
				Description: "AES-128 is discouraged, prefer AES-256",
				Finding:     Finding{ID: "FIND-011", Name: "AES-128-GCM", AssetType: AssetAlgorithm},
				Result:      PolicyWarn,
				Severity:    SeverityLow,
			},
		},
		Summary: PolicySummary{
			TotalFindings: 5,
			PassCount:     3,
			FailCount:     1,
			WarnCount:     1,
		},
	}

	if len(report.Violations) != 2 {
		t.Errorf("PolicyReport.Violations length = %d, want %d", len(report.Violations), 2)
	}
	if report.Violations[0].Result != PolicyFail {
		t.Errorf("Violation[0].Result = %q, want %q", report.Violations[0].Result, PolicyFail)
	}
	if report.Violations[1].Result != PolicyWarn {
		t.Errorf("Violation[1].Result = %q, want %q", report.Violations[1].Result, PolicyWarn)
	}
	if report.Summary.TotalFindings != 5 {
		t.Errorf("Summary.TotalFindings = %d, want %d", report.Summary.TotalFindings, 5)
	}
	if report.Summary.PassCount+report.Summary.FailCount+report.Summary.WarnCount != report.Summary.TotalFindings {
		t.Error("Summary counts do not add up to TotalFindings")
	}
}
