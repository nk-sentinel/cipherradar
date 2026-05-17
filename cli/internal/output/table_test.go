package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestTableWriter_EmptyResultStillProducesLine(t *testing.T) {
	var buf bytes.Buffer
	w := &TableWriter{}
	if err := w.WriteScanResult(&buf, &types.ScanResult{}); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("empty result should produce 'no findings'; got %q", buf.String())
	}
}

func TestTableWriter_HeaderAndSortOrder(t *testing.T) {
	now := time.Now()
	result := &types.ScanResult{
		StartTime: now,
		EndTime:   now,
		Findings: []types.Finding{
			{
				Name:     "RSA-2048",
				RuleID:   "cbom-py-rsa-2048",
				Severity: types.SeverityLow,
				Location: types.Location{File: "b.py", StartLine: 3},
			},
			{
				Name:     "MD5",
				RuleID:   "cbom-py-hashlib-md5",
				Severity: types.SeverityHigh,
				Location: types.Location{File: "a.py", StartLine: 10},
			},
		},
	}
	var buf bytes.Buffer
	w := &TableWriter{}
	if err := w.WriteScanResult(&buf, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header + 2 rows; got:\n%s", out)
	}
	if !strings.Contains(lines[0], "SEVERITY") || !strings.Contains(lines[0], "RULE") {
		t.Errorf("header missing: %q", lines[0])
	}
	// High severity must sort above low regardless of file ordering.
	if !strings.Contains(lines[1], "MD5") {
		t.Errorf("expected MD5 (high) first; got: %q", lines[1])
	}
	if !strings.Contains(lines[2], "RSA-2048") {
		t.Errorf("expected RSA-2048 (low) second; got: %q", lines[2])
	}
	// Location format is file:line.
	if !strings.Contains(out, "a.py:10") {
		t.Errorf("expected file:line rendering 'a.py:10'; got:\n%s", out)
	}
}

func TestTableWriter_RegisteredInFactory(t *testing.T) {
	w, err := WriterFactory("table")
	if err != nil {
		t.Fatalf("WriterFactory(table): %v", err)
	}
	if w.Format() != "table" {
		t.Errorf("Format() = %q; want table", w.Format())
	}
}
