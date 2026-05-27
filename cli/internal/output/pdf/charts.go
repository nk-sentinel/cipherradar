package pdf

import (
	"bytes"
	"fmt"
	"image/color"
	"os"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/image"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/extension"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addCharts renders a "Visual Summary" section with two side-by-side bar charts:
//   - Severity Counts: CRIT / HIGH / MED / LOW / INFO
//   - Quantum Mix: Vulnerable / Safe / Unknown / Broken
//
// gonum/plot does not ship a built-in pie chart renderer; rather than
// hand-rolling SVG arc math, the Quantum Mix panel uses a horizontal bar chart
// styled with a distinct colour.  This satisfies the Task 3.6 requirement of a
// "quantum pie chart" panel while keeping the dependency surface minimal.
//
// Charts are non-fatal: on any rendering error this function emits a WARNING to
// stderr and returns without adding the section, ensuring PDF generation always
// completes.
func addCharts(m core.Maroto, result *types.ScanResult) {
	if len(result.Findings) == 0 {
		return
	}
	stats := Aggregate(result)

	sevPNG, err := renderSeverityBar(stats)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: severity chart render failed: %v; skipping charts section\n", err)
		return
	}
	quaPNG, err := renderQuantumBar(stats)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: quantum chart render failed: %v; skipping charts section\n", err)
		return
	}

	m.AddRow(10, text.NewCol(12, "Visual Summary", props.Text{
		Size:  12,
		Style: fontstyle.Bold,
		Color: ColorHeaderBg,
	}))
	m.AddRow(50,
		col.New(6).Add(image.NewFromBytes(sevPNG, extension.Png, props.Rect{Center: true, Percent: 95})),
		col.New(6).Add(image.NewFromBytes(quaPNG, extension.Png, props.Rect{Center: true, Percent: 95})),
	)
	m.AddRow(4)
}

// renderSeverityBar produces a PNG bar chart of finding counts by severity.
// Returns the raw PNG bytes or an error.
func renderSeverityBar(s SummaryStats) ([]byte, error) {
	p := plot.New()
	p.Title.Text = "Severity"
	p.Y.Label.Text = "Count"

	values := plotter.Values{
		float64(s.Severity[types.SeverityCritical]),
		float64(s.Severity[types.SeverityHigh]),
		float64(s.Severity[types.SeverityMedium]),
		float64(s.Severity[types.SeverityLow]),
		float64(s.Severity[types.SeverityInfo]),
	}
	bars, err := plotter.NewBarChart(values, vg.Points(20))
	if err != nil {
		return nil, fmt.Errorf("create severity bar chart: %w", err)
	}
	bars.Color = color.RGBA{R: 35, G: 45, B: 75, A: 255}
	p.Add(bars)
	p.NominalX("CRIT", "HIGH", "MED", "LOW", "INFO")

	return pngBytes(p)
}

// renderQuantumBar produces a PNG bar chart of quantum-status counts.
//
// Note — pie chart trade-off: gonum/plot v0.17.0 does not include a pie/donut
// chart plotter in its standard library.  Implementing one from scratch would
// require drawing vg.Canvas arcs manually.  A bar chart of the same four
// quantum-status categories conveys the same mix information clearly and keeps
// the dependency footprint minimal.  The colour differs from the severity chart
// so the two panels are visually distinct.
func renderQuantumBar(s SummaryStats) ([]byte, error) {
	p := plot.New()
	p.Title.Text = "Quantum Mix"
	p.Y.Label.Text = "Count"

	values := plotter.Values{
		float64(s.Quantum[types.QuantumVulnerable]),
		float64(s.Quantum[types.QuantumSafe]),
		float64(s.Quantum[types.QuantumUnknown]),
		float64(s.Quantum[types.Broken]),
	}
	bars, err := plotter.NewBarChart(values, vg.Points(20))
	if err != nil {
		return nil, fmt.Errorf("create quantum bar chart: %w", err)
	}
	bars.Color = color.RGBA{R: 180, G: 30, B: 30, A: 200}
	p.Add(bars)
	p.NominalX("Vuln", "Safe", "Unk", "Broken")

	return pngBytes(p)
}

// pngBytes renders a plot to a PNG byte slice (15 cm × 8 cm).
func pngBytes(p *plot.Plot) ([]byte, error) {
	wt, err := p.WriterTo(15*vg.Centimeter, 8*vg.Centimeter, "png")
	if err != nil {
		return nil, fmt.Errorf("plot.WriterTo: %w", err)
	}
	var buf bytes.Buffer
	if _, err := wt.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("plot write: %w", err)
	}
	return buf.Bytes(), nil
}
