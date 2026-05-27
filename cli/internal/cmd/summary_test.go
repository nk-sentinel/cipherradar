package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestEmitFinalSummary_DuplicationAvoidanceRules(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			{Severity: types.SeverityCritical}, {Severity: types.SeverityHigh},
			{Severity: types.SeverityMedium}, {Severity: types.SeverityLow},
		},
		StartTime: time.Now().Add(-2 * time.Second),
		EndTime:   time.Now(),
	}
	for _, tc := range []struct {
		name      string
		paths     []ResolvedOutput
		stdoutFmt string
		wantEmit  bool
		wantPaths int
	}{
		{"TTY+default text → suppress", nil, "text", false, 0},
		{"pipe+default JSON → emit, no paths", nil, "cyclonedx-json", true, 0},
		{"-o single file → emit with one path", []ResolvedOutput{{Path: "/tmp/x.json", Format: "cyclonedx-json", Size: 1024}}, "", true, 1},
		{"-o multi → emit with both paths", []ResolvedOutput{{Path: "/tmp/x.json", Format: "cyclonedx-json", Size: 1024}, {Path: "/tmp/y.pdf", Format: "pdf", Size: 32768}}, "", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			emitFinalSummary(&buf, result, tc.paths, tc.stdoutFmt, false)
			out := buf.String()
			if tc.wantEmit && !strings.Contains(out, "[scan] complete") {
				t.Errorf("expected emission, got: %q", out)
			}
			if !tc.wantEmit && out != "" {
				t.Errorf("expected suppression, got: %q", out)
			}
			pathLines := strings.Count(out, "[scan] wrote")
			if pathLines != tc.wantPaths {
				t.Errorf("path lines = %d, want %d:\n%s", pathLines, tc.wantPaths, out)
			}
		})
	}
}

func TestEmitFinalSummary_QuietSuppresses(t *testing.T) {
	var buf bytes.Buffer
	result := &types.ScanResult{Findings: []types.Finding{{Severity: types.SeverityCritical}}}
	emitFinalSummary(&buf, result, []ResolvedOutput{{Path: "/tmp/x.json", Format: "cyclonedx-json"}}, "", true)
	if buf.Len() != 0 {
		t.Errorf("--quiet must suppress everything; got: %q", buf.String())
	}
}
