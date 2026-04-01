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
				Pass:      1,
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
				Pass:      1,
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
				Pass:      1,
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
				Pass:      1,
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
				Pass:      1,
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
	if !strings.Contains(out, "CipherRadar") {
		t.Error("output should contain 'CipherRadar'")
	}
	if !strings.Contains(out, "Cryptography Bill of Materials Scanner") {
		t.Error("output should contain scanner description")
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

func TestTextWriter_ContainsScanComplete(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SCAN COMPLETE") {
		t.Error("output should contain 'SCAN COMPLETE'")
	}
	if !strings.Contains(out, "5 findings") {
		t.Error("output should contain '5 findings'")
	}
}

func TestTextWriter_ContainsSeverityRows(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CRITICAL") {
		t.Error("output should contain 'CRITICAL'")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("output should contain 'HIGH'")
	}
	if !strings.Contains(out, "MEDIUM") {
		t.Error("output should contain 'MEDIUM'")
	}
}

func TestTextWriter_SeverityOrder(t *testing.T) {
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
	medIdx := strings.Index(out, "MEDIUM")
	if critIdx < 0 || highIdx < 0 || medIdx < 0 {
		t.Fatal("output should contain CRITICAL, HIGH, and MEDIUM")
	}
	if critIdx > highIdx {
		t.Error("CRITICAL should appear before HIGH")
	}
	if highIdx > medIdx {
		t.Error("HIGH should appear before MEDIUM")
	}
}

func TestTextWriter_ContainsQuantumReadiness(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Quantum Readiness:") {
		t.Error("output should contain 'Quantum Readiness:'")
	}
	if !strings.Contains(out, "quantum-safe") {
		t.Error("output should mention quantum-safe count")
	}
}

func TestTextWriter_ContainsQuantumVulnerable(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Quantum Vulnerable:") {
		t.Error("output should contain 'Quantum Vulnerable:' when there are vulnerable findings")
	}
}

func TestTextWriter_ContainsFindingNames(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CERT_NONE") {
		t.Error("output should contain the CERT_NONE finding")
	}
	if !strings.Contains(out, "MD5") {
		t.Error("output should contain the MD5 finding")
	}
}

func TestTextWriter_ContainsPassInfo(t *testing.T) {
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Pass 1") {
		t.Error("output should contain pass information")
	}
	if !strings.Contains(out, "AST") {
		t.Error("output should label Pass 1 as AST")
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
	if !strings.Contains(out, "SCAN COMPLETE: 0 findings") {
		t.Error("output should contain 'SCAN COMPLETE: 0 findings'")
	}
}

func TestTextWriter_NoColorInBuffer(t *testing.T) {
	// Writing to a bytes.Buffer (not a terminal) should produce no ANSI codes
	result := newTextTestScanResult()
	w := &TextWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Error("output to non-terminal should not contain ANSI escape codes")
	}
}
