package output

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// newPDFTestScanResult creates a ScanResult with findings at every severity level
// and a mix of quantum statuses for PDF testing.
func newPDFTestScanResult() *types.ScanResult {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	return &types.ScanResult{
		Target:       "/home/user/test-project",
		StartTime:    now,
		EndTime:      now.Add(2500 * time.Millisecond),
		PassesRun:    []int{1, 2},
		FilesScanned: 128,
		Findings: []types.Finding{
			{
				ID:          "FIND-001",
				AssetType:   types.AssetAlgorithm,
				Name:        "MD5",
				Location:    types.Location{File: "crypto_utils.py", StartLine: 12, StartCol: 3},
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Description: "broken hash algorithm",
				RuleID:      "cbom-hash-md5",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.Broken,
					AlgorithmFamily: "md5",
				},
			},
			{
				ID:          "FIND-002",
				AssetType:   types.AssetAlgorithm,
				Name:        "AES-256-CBC",
				Location:    types.Location{File: "encrypt.py", StartLine: 8, StartCol: 5},
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Description: "AES in CBC mode",
				RuleID:      "cbom-cipher-aes-cbc",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.QuantumVulnerable,
					AlgorithmFamily: "aes",
				},
			},
			{
				ID:          "FIND-003",
				AssetType:   types.AssetAlgorithm,
				Name:        "SHA-256",
				Location:    types.Location{File: "hash.py", StartLine: 5, StartCol: 1},
				Severity:    types.SeverityInfo,
				Confidence:  types.ConfidenceHigh,
				Description: "SHA-256 hash",
				RuleID:      "cbom-hash-sha256",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.QuantumSafe,
					AlgorithmFamily: "sha",
				},
			},
			{
				ID:          "FIND-004",
				AssetType:   types.AssetCertificate,
				Name:        "CERT_NONE",
				Location:    types.Location{File: "ssl_usage.py", StartLine: 8, StartCol: 5},
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceHigh,
				Description: "disabled certificate validation",
				RuleID:      "cbom-cert-none",
				Properties: types.CryptoProperties{
					QuantumStatus: types.QuantumUnknown,
				},
			},
			{
				ID:          "FIND-005",
				AssetType:   types.AssetAlgorithm,
				Name:        "RSA-2048",
				Location:    types.Location{File: "keygen.py", StartLine: 3, StartCol: 1},
				Severity:    types.SeverityLow,
				Confidence:  types.ConfidenceHigh,
				Description: "RSA key generation",
				RuleID:      "cbom-pke-rsa",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.QuantumVulnerable,
					AlgorithmFamily: "rsa",
				},
			},
		},
	}
}

func TestPDFWriter_Format(t *testing.T) {
	w := &PDFWriter{}
	if got := w.Format(); got != "pdf" {
		t.Errorf("Format() = %q, want %q", got, "pdf")
	}
}

func TestPDFWriter_WriteScanResult_ProducesOutput(t *testing.T) {
	result := newPDFTestScanResult()
	w := &PDFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriteScanResult produced empty output")
	}
}

func TestPDFWriter_WriteScanResult_PDFMagicBytes(t *testing.T) {
	result := newPDFTestScanResult()
	w := &PDFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	data := buf.Bytes()
	if len(data) < 4 {
		t.Fatalf("PDF output is too short: %d bytes", len(data))
	}

	magic := string(data[:5])
	if magic != "%PDF-" {
		t.Errorf("PDF output does not start with %%PDF- magic bytes, got: %q", magic)
	}
}

func TestPDFWriter_WriteScanResult_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		Target:       "/tmp/empty",
		StartTime:    time.Now(),
		EndTime:      time.Now().Add(100 * time.Millisecond),
		PassesRun:    []int{1},
		FilesScanned: 0,
		Findings:     []types.Finding{},
	}

	w := &PDFWriter{}
	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriteScanResult produced empty output for zero findings")
	}

	// Verify it's still a valid PDF.
	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("Empty findings PDF should still start with %%PDF-, got: %q", magic)
	}
}

func TestPDFWriter_WriteScanResult_AllSeverityLevels(t *testing.T) {
	result := newPDFTestScanResult()
	w := &PDFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	// Verify the output is a reasonable size (should be at least a few KB with content).
	if buf.Len() < 1000 {
		t.Errorf("PDF output seems too small for 5 findings: %d bytes", buf.Len())
	}

	// Verify PDF magic bytes.
	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("PDF should start with %%PDF-, got: %q", magic)
	}
}

func TestPDFWriter_WriterFactory_Integration(t *testing.T) {
	w, err := WriterFactory("pdf")
	if err != nil {
		t.Fatalf("WriterFactory(\"pdf\") returned error: %v", err)
	}

	if w.Format() != "pdf" {
		t.Errorf("WriterFactory(\"pdf\").Format() = %q, want %q", w.Format(), "pdf")
	}

	result := newPDFTestScanResult()
	var buf bytes.Buffer
	err = w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriterFactory PDF writer produced empty output")
	}

	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("WriterFactory PDF should start with %%PDF-, got: %q", magic)
	}
}

func TestPDFWriter_WriteScanResult_LargeNumberOfFindings(t *testing.T) {
	now := time.Now()
	result := &types.ScanResult{
		Target:       "/large/project",
		StartTime:    now,
		EndTime:      now.Add(10 * time.Second),
		PassesRun:    []int{1, 2, 3},
		FilesScanned: 5000,
		Findings:     make([]types.Finding, 0, 50),
	}

	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	statuses := []types.QuantumStatus{
		types.QuantumVulnerable,
		types.QuantumSafe,
		types.QuantumUnknown,
		types.Broken,
	}

	for i := 0; i < 50; i++ {
		result.Findings = append(result.Findings, types.Finding{
			ID:          fmt.Sprintf("FIND-%03d", i+1),
			AssetType:   types.AssetAlgorithm,
			Name:        fmt.Sprintf("ALGO-%d", i),
			Location:    types.Location{File: fmt.Sprintf("pkg/module%d/crypto.go", i), StartLine: i*10 + 1},
			Severity:    severities[i%len(severities)],
			Confidence:  types.ConfidenceHigh,
			Description: fmt.Sprintf("Test finding %d for algorithm ALGO-%d", i, i),
			RuleID:      fmt.Sprintf("rule-%03d", i),
			Properties: types.CryptoProperties{
				QuantumStatus:   statuses[i%len(statuses)],
				AlgorithmFamily: fmt.Sprintf("algo-family-%d", i%5),
			},
		})
	}

	w := &PDFWriter{}
	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error for large findings set: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriteScanResult produced empty output for large findings set")
	}

	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("Large findings PDF should start with %%PDF-, got: %q", magic)
	}
}
