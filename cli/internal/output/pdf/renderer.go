// Package pdf renders CipherRadar CBOM scan results as a multi-section
// PDF report (Option D layout — see docs/superpowers/specs/...).
//
// File layout (added in feature/cbom-export-quality phase 3):
//   - shared.go        — colors, severity helpers
//   - renderer.go      — entry + orchestration
//   - cover.go         — addCover
//   - findings.go      — addFindings (preserved from pre-split pdf.go)
//   - summary.go       — Aggregate + addSummary (Option D breakdowns)
//   - quantum.go       — addQuantum (migration backlog)
//   - charts.go        — addCharts (gonum/plot SVG/PNG)
//   - compliance.go    — addCompliance (stub for future framework integration)
//   - diff.go          — addBaselineDiff (uses cli/internal/diff)
package pdf

import (
	"fmt"
	"io"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Options controls optional PDF features.
type Options struct {
	// Baseline, when non-nil, enables the "Changes vs Baseline" section.
	// The value is a parsed CycloneDX BOM loaded via diff.LoadBOM.
	Baseline *output.BOM
}

// Writer generates a detailed PDF report from scan results.
type Writer struct {
	Opts Options
}

func init() {
	output.RegisterWriter("pdf", func() output.Writer { return &Writer{} })
}

// Format returns the name of this output format.
func (w *Writer) Format() string { return "pdf" }

// WriteScanResult writes the PDF report bytes to wr.
func (w *Writer) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	doc, err := generate(result, w.Opts)
	if err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}
	b := doc.GetBytes()
	if _, err := wr.Write(b); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}
	return nil
}

func generate(result *types.ScanResult, opts Options) (core.Document, error) {
	cfg := config.NewBuilder().
		WithPageNumber(props.PageNumber{
			Pattern: "Page {current} of {total}",
			Place:   props.RightBottom,
			Size:    8,
			Color:   ColorInfo,
		}).
		WithLeftMargin(10).WithTopMargin(15).WithRightMargin(10).WithBottomMargin(15).
		WithCreator("CipherRadar", true).
		WithTitle("CipherRadar CBOM Scan Report", true).
		Build()

	m := maroto.New(cfg)

	// Section calls — each is wired by a subsequent Phase 3 task.
	// Commented out until the section file is implemented so the package
	// compiles cleanly during incremental phase rollout.
	//
	addCover(m, result)   // Task 3.2
	addSummary(m, result) // Task 3.3
	addCharts(m, result)  // Task 3.6
	if len(result.Findings) > 0 {
		addFindings(m, result) // Task 3.4
		addQuantum(m, result)  // Task 3.5
	}
	addCompliance(m, result) // Task 3.7
	if opts.Baseline != nil {
		addBaselineDiff(m, result, opts.Baseline) // Task 3.8
	}
	addFooter(m) // Task 3.4

	return m.Generate()
}
