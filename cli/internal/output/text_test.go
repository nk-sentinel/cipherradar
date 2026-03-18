package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func newTextTestScanResult() *types.ScanResult {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	return &types.ScanResult{
		Target:       "./test-project",
		StartTime:    now,
		EndTime:      now.Add(1230 * time.Millisecond),
		PassesRun:    []int{1},
		FilesScanned: 42,
		Findings: []types.Finding{
			{
				ID:        "FIND-001",
				AssetType: types.AssetAlgorithm,
				Name:      "MD5",
				Location: types.Location{
					File:      "crypto.py",
					StartLine: 12,
					StartCol:  3,
				},
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Description: "broken hash algorithm",
				Properties: types.CryptoProperties{
					QuantumStatus: types.Broken,
				},
			},
			{
				ID:        "FIND-002",
				AssetType: types.AssetAlgorithm,
				Name:      "AES-256-CBC",
				Location: types.Location{
					File:      "encrypt.py",
					StartLine: 8,
					StartCol:  5,
				},
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Description: "AES in CBC mode",
				Properties: types.CryptoProperties{
					QuantumStatus: types.QuantumVulnerable,
				},
			},
			{
				ID:        "FIND-003",
				AssetType: types.AssetAlgorithm,
				Name:      "SHA-256",
				Location: types.Location{
					File:      "hash.py",
					StartLine: 5,
					StartCol:  1,
				},
				Severity:    types.SeverityInfo,
				Confidence:  types.ConfidenceHigh,
				Description: "SHA-256 hash",
				Properties: types.CryptoProperties{
					QuantumStatus: types.QuantumSafe,
				},
			},
			{
				ID:        "FIND-004",
				AssetType: types.AssetCertificate,
				Name:      "CERT_NONE",
				Location: types.Location{
					File:      "ssl_usage.py",
					StartLine: 8,
					StartCol:  5,
				},
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceHigh,
				Description: "disabled certificate validation",
				Properties: types.CryptoProperties{
					QuantumStatus: types.QuantumUnknown,
				},
			},
			{
				ID:        "FIND-005",
				AssetType: types.AssetAlgorithm,
				Name:      "RSA-2048",
				Location: types.Location{
					File:      "keygen.py",
					StartLine: 3,
					StartCol:  1,
				},
				Severity:    types.SeverityLow,
				Confidence:  types.ConfidenceHigh,
				Description: "RSA key generation",
				Properties: types.CryptoProperties{
					QuantumStatus: types.QuantumVulnerable,
				},
			},
		},
	}
}

func TestTextWriter_ContainsHeader(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CipherRadar Scan Results") {
		t.Error("output should contain 'CipherRadar Scan Results'")
	}
}

func TestTextWriter_ContainsTarget(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "./test-project") {
		t.Error("output should contain the target path")
	}
}

func TestTextWriter_ContainsFileCount(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "42 scanned") {
		t.Error("output should contain '42 scanned'")
	}
}

func TestTextWriter_ContainsSeverityCounts(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Findings: 5") {
		t.Error("output should contain 'Findings: 5'")
	}
	if !strings.Contains(out, "CRITICAL: 1") {
		t.Error("output should contain 'CRITICAL: 1'")
	}
	if !strings.Contains(out, "HIGH:     1") {
		t.Error("output should contain 'HIGH:     1'")
	}
	if !strings.Contains(out, "MEDIUM:   1") {
		t.Error("output should contain 'MEDIUM:   1'")
	}
	if !strings.Contains(out, "LOW:      1") {
		t.Error("output should contain 'LOW:      1'")
	}
	if !strings.Contains(out, "INFO:     1") {
		t.Error("output should contain 'INFO:     1'")
	}
}

func TestTextWriter_ContainsQuantumStatus(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Quantum Status:") {
		t.Error("output should contain 'Quantum Status:'")
	}
	if !strings.Contains(out, "Vulnerable: 2") {
		t.Error("output should contain 'Vulnerable: 2'")
	}
	if !strings.Contains(out, "Safe:       1") {
		t.Error("output should contain 'Safe:       1'")
	}
	if !strings.Contains(out, "Broken:     1") {
		t.Error("output should contain 'Broken:     1'")
	}
}

func TestTextWriter_ContainsTopFindings(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Top Findings:") {
		t.Error("output should contain 'Top Findings:'")
	}
	// Critical finding should appear first.
	if !strings.Contains(out, "CERT_NONE") {
		t.Error("output should contain the CERT_NONE finding")
	}
	if !strings.Contains(out, "MD5") {
		t.Error("output should contain the MD5 finding")
	}
}

func TestTextWriter_TopFindingsSeverityOrder(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	critIdx := strings.Index(out, "CRITICAL")
	highIdx := strings.Index(out, "HIGH")
	if critIdx < 0 || highIdx < 0 {
		t.Fatal("output should contain both CRITICAL and HIGH findings")
	}
	// Within the Top Findings section, CRITICAL should appear before HIGH.
	topIdx := strings.Index(out, "Top Findings:")
	critPos := strings.Index(out[topIdx:], "CRITICAL")
	highPos := strings.Index(out[topIdx:], "HIGH")
	if critPos > highPos {
		t.Error("CRITICAL findings should appear before HIGH findings in Top Findings")
	}
}

func TestTextWriter_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		Target:       "/tmp/empty",
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		PassesRun:    []int{1},
		FilesScanned: 0,
	}

	w := &TextWriter{}
	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Findings: 0") {
		t.Error("output should contain 'Findings: 0'")
	}
	if strings.Contains(out, "Top Findings:") {
		t.Error("output should not contain 'Top Findings:' when there are no findings")
	}
}
