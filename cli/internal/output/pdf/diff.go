package pdf

import (
	"fmt"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/diff"
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addBaselineDiff renders a "Changes vs Baseline" section comparing the
// current scan's CBOM against the provided baseline BOM. It uses
// cli/internal/diff.CompareBOMs and lists added, removed, and changed
// components, as well as an unchanged count.
//
// The actual diff API found in cli/internal/diff/diff.go:
//   - Function:  diff.CompareBOMs(before, after *output.BOM) *diff.DiffResult
//   - Result:    Added []output.Component, Removed []output.Component,
//     Changed []diff.ChangedComponent, Unchanged int (count, not slice)
//
// output.Component carries Name, BOMRef, Evidence.Occurrences[].{Location,Line},
// and CryptoProperties.AssetType — no Severity or Finding-style location fields.
func addBaselineDiff(m core.Maroto, result *types.ScanResult, baseline *output.BOM) {
	if baseline == nil {
		return
	}

	// Build an output.BOM from the current scan result so CompareBOMs can
	// operate on the same type. output.ConvertScanResult is the canonical
	// converter used by the CycloneDX JSON writer.
	current := output.ConvertScanResult(result)

	d := diff.CompareBOMs(baseline, current)
	if d == nil {
		return
	}

	// Section header.
	m.AddRow(10, text.NewCol(12, "Changes vs Baseline", props.Text{
		Size:  14,
		Style: fontstyle.Bold,
		Color: ColorHeaderBg,
	}))

	// Summary tile: counts of added, removed, changed, unchanged.
	summary := fmt.Sprintf(
		"Added: %d   Removed: %d   Changed: %d   Unchanged: %d",
		len(d.Added), len(d.Removed), len(d.Changed), d.Unchanged,
	)
	m.AddRow(7, col.New(12).Add(text.New(summary, props.Text{
		Size:  11,
		Align: align.Center,
		Color: ColorDarkGray,
		Style: fontstyle.Bold,
	})))
	m.AddRow(4)

	// Added components (top 10).
	if len(d.Added) > 0 {
		m.AddRow(8, text.NewCol(12, fmt.Sprintf("New Components (%d)", len(d.Added)), props.Text{
			Size:  11,
			Style: fontstyle.Bold,
			Color: ColorCritical,
		}))
		shown := d.Added
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, c := range shown {
			m.AddRow(5, col.New(12).Add(text.New(
				componentSummaryLine(c),
				props.Text{Size: 8, Color: ColorCritical, Align: align.Left, Left: 2},
			)))
		}
		if len(d.Added) > 10 {
			m.AddRow(5, col.New(12).Add(text.New(
				fmt.Sprintf("  ... and %d more", len(d.Added)-10),
				props.Text{Size: 8, Color: ColorDarkGray},
			)))
		}
		m.AddRow(3)
	}

	// Removed components (top 10).
	if len(d.Removed) > 0 {
		m.AddRow(8, text.NewCol(12, fmt.Sprintf("Resolved Components (%d)", len(d.Removed)), props.Text{
			Size:  11,
			Style: fontstyle.Bold,
			Color: ColorPass,
		}))
		shown := d.Removed
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, c := range shown {
			m.AddRow(5, col.New(12).Add(text.New(
				componentSummaryLine(c),
				props.Text{Size: 8, Color: ColorPass, Align: align.Left, Left: 2},
			)))
		}
		if len(d.Removed) > 10 {
			m.AddRow(5, col.New(12).Add(text.New(
				fmt.Sprintf("  ... and %d more", len(d.Removed)-10),
				props.Text{Size: 8, Color: ColorDarkGray},
			)))
		}
		m.AddRow(3)
	}

	// Changed components (top 10) with their change descriptions.
	if len(d.Changed) > 0 {
		m.AddRow(8, text.NewCol(12, fmt.Sprintf("Modified Components (%d)", len(d.Changed)), props.Text{
			Size:  11,
			Style: fontstyle.Bold,
			Color: ColorMedium,
		}))

		headerStyle := &props.Cell{BackgroundColor: ColorHeaderBg}
		headerText := props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center, Top: 2, Color: ColorWhite}
		m.AddRow(7,
			col.New(4).Add(text.New("Component", headerText)).WithStyle(headerStyle),
			col.New(8).Add(text.New("Changes", headerText)).WithStyle(headerStyle),
		)

		shown := d.Changed
		if len(shown) > 10 {
			shown = shown[:10]
		}
		cell := props.Text{Size: 7, Top: 1.5, Color: &props.BlackColor, Align: align.Left, Left: 1}
		rowStyle := &props.Cell{
			BackgroundColor: BgMedium,
			BorderType:      border.Full,
			BorderColor:     ColorLightGray,
			BorderThickness: 0.1,
		}
		for _, cc := range shown {
			changesText := ""
			for i, ch := range cc.Changes {
				if i > 0 {
					changesText += "; "
				}
				changesText += ch
			}
			m.AddAutoRow(
				col.New(4).Add(text.New(cc.Name, props.Text{
					Size: 7, Style: fontstyle.Bold, Top: 1.5, Left: 1, Color: &props.BlackColor,
				})).WithStyle(rowStyle),
				col.New(8).Add(text.New(changesText, cell)).WithStyle(rowStyle),
			)
		}
		if len(d.Changed) > 10 {
			m.AddRow(5, col.New(12).Add(text.New(
				fmt.Sprintf("  ... and %d more", len(d.Changed)-10),
				props.Text{Size: 8, Color: ColorDarkGray},
			)))
		}
		m.AddRow(3)
	}

	m.AddRow(4)
}

// componentSummaryLine formats a single output.Component for a compact list row.
// Uses Evidence.Occurrences for location when available; falls back to BOMRef or
// name-only when evidence is absent (e.g. for components without source locations).
func componentSummaryLine(c output.Component) string {
	assetType := ""
	if c.CryptoProperties != nil {
		assetType = string(c.CryptoProperties.AssetType)
	}

	loc := ""
	if c.Evidence != nil && len(c.Evidence.Occurrences) > 0 {
		occ := c.Evidence.Occurrences[0]
		if occ.Line > 0 {
			loc = fmt.Sprintf(" — %s:%d", occ.Location, occ.Line)
		} else if occ.Location != "" {
			loc = fmt.Sprintf(" — %s", occ.Location)
		}
	} else if c.BOMRef != "" && c.BOMRef != c.Name {
		loc = fmt.Sprintf(" [%s]", c.BOMRef)
	}

	if assetType != "" {
		return fmt.Sprintf("  %s (%s)%s", c.Name, assetType, loc)
	}
	return fmt.Sprintf("  %s%s", c.Name, loc)
}
