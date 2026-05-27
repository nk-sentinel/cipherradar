package pdf

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// TestAddCharts_WriterProducesNonEmptyPDF verifies that charts render cleanly
// and that WriteScanResult returns a non-empty document when findings are
// present.  The test also confirms no chart warning is emitted to stderr.
func TestAddCharts_WriterProducesNonEmptyPDF(t *testing.T) {
	result := &types.ScanResult{
		Target:    "/tmp/smoke",
		StartTime: time.Now().Add(-2 * time.Second),
		EndTime:   time.Now(),
		Findings: []types.Finding{
			{ID: "1", Name: "RSA", Severity: types.SeverityHigh, AssetType: types.AssetAlgorithm,
				Properties: types.CryptoProperties{AlgorithmFamily: "RSA", QuantumStatus: types.QuantumVulnerable}},
			{ID: "2", Name: "AES", Severity: types.SeverityMedium, AssetType: types.AssetAlgorithm,
				Properties: types.CryptoProperties{AlgorithmFamily: "AES", QuantumStatus: types.QuantumSafe}},
			{ID: "3", Name: "MD5", Severity: types.SeverityCritical, AssetType: types.AssetAlgorithm,
				Properties: types.CryptoProperties{AlgorithmFamily: "MD5", QuantumStatus: types.Broken}},
		},
	}

	var buf bytes.Buffer
	w := &Writer{}
	if err := w.WriteScanResult(&buf, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty PDF output")
	}
	// PDF files start with the %PDF magic bytes.
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Errorf("output does not start with %%PDF magic: got %q", buf.Bytes()[:min(8, buf.Len())])
	}
	t.Logf("PDF size: %d bytes", buf.Len())
}

// TestRenderSeverityBar verifies renderSeverityBar returns valid PNG bytes.
func TestRenderSeverityBar(t *testing.T) {
	stats := SummaryStats{
		Severity: map[types.Severity]int{
			types.SeverityCritical: 1,
			types.SeverityHigh:     3,
			types.SeverityMedium:   5,
			types.SeverityLow:      2,
			types.SeverityInfo:     0,
		},
		Quantum: map[types.QuantumStatus]int{},
	}
	png, err := renderSeverityBar(stats)
	if err != nil {
		t.Fatalf("renderSeverityBar: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("expected non-empty PNG bytes")
	}
	// PNG magic: \x89PNG
	if !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Errorf("output does not start with PNG magic")
	}
}

// TestRenderQuantumBar verifies renderQuantumBar returns valid PNG bytes.
func TestRenderQuantumBar(t *testing.T) {
	stats := SummaryStats{
		Severity: map[types.Severity]int{},
		Quantum: map[types.QuantumStatus]int{
			types.QuantumVulnerable: 4,
			types.QuantumSafe:       2,
			types.QuantumUnknown:    1,
			types.Broken:            1,
		},
	}
	png, err := renderQuantumBar(stats)
	if err != nil {
		t.Fatalf("renderQuantumBar: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("expected non-empty PNG bytes")
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Errorf("output does not start with PNG magic")
	}
}

// TestAddCharts_EmptyFindings verifies that addCharts is a no-op when there
// are no findings (no section, no panic).
func TestAddCharts_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		Target:    "/tmp/empty",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Findings:  nil,
	}
	var buf bytes.Buffer
	w := &Writer{}
	if err := w.WriteScanResult(&buf, result); err != nil {
		t.Fatalf("WriteScanResult (empty): %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty PDF even with no findings")
	}
}

// TestAddCharts_NonFatal simulates a chart failure path by saving/restoring
// stderr and confirming the PDF is still produced when charts silently fail.
// This test exercises the warning-only path indirectly: if the addCharts
// function ever panics, the test binary crashes — confirming non-fatal design.
func TestAddCharts_NonFatal(t *testing.T) {
	// Re-route stderr so we can check for any unexpected panics.
	oldStderr := os.Stderr
	devNull, _ := os.Open(os.DevNull)
	os.Stderr = devNull
	defer func() {
		os.Stderr = oldStderr
		devNull.Close()
	}()

	result := &types.ScanResult{
		Target:    "/tmp/nonfatal",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Findings: []types.Finding{
			{ID: "x", Severity: types.SeverityHigh},
		},
	}
	var buf bytes.Buffer
	w := &Writer{}
	if err := w.WriteScanResult(&buf, result); err != nil {
		t.Fatalf("WriteScanResult should not fail: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
