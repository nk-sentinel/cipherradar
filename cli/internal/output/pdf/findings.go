package pdf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addFindings renders the detailed findings table.
// Extracted from cli/internal/output/pdf.go addFindingsTable.
func addFindings(m core.Maroto, result *types.ScanResult) {
	// Section header.
	m.AddRow(10,
		text.NewCol(12, "Detailed Findings", props.Text{
			Size:  14,
			Style: fontstyle.Bold,
			Color: ColorHeaderBg,
		}),
	)

	m.AddRow(3)

	// Table header row.
	headerStyle := &props.Cell{
		BackgroundColor: ColorHeaderBg,
	}
	headerText := props.Text{
		Size:  8,
		Style: fontstyle.Bold,
		Align: align.Center,
		Top:   2,
		Color: ColorWhite,
	}

	// Grid widths must match the body rows below: 1+3+1+2+4+1 = 12.
	// "Quantum" label kept short for the narrow 1/12 column.
	m.AddRow(8,
		col.New(1).Add(text.New("Severity", headerText)).WithStyle(headerStyle),
		col.New(3).Add(text.New("File", headerText)).WithStyle(headerStyle),
		col.New(1).Add(text.New("Line", headerText)).WithStyle(headerStyle),
		col.New(2).Add(text.New("Name", headerText)).WithStyle(headerStyle),
		col.New(4).Add(text.New("Description", headerText)).WithStyle(headerStyle),
		col.New(1).Add(text.New("Quantum", headerText)).WithStyle(headerStyle),
	)

	// Sort findings by severity (CRITICAL first).
	sorted := make([]types.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return SeverityOrder(sorted[i].Severity) < SeverityOrder(sorted[j].Severity)
	})

	// Add a row for each finding.
	for i, f := range sorted {
		sevLabel := strings.ToUpper(string(f.Severity))
		sevColor := SeverityColor(f.Severity)
		bgColor := SeverityBgColor(f.Severity)

		// Alternate row shading for non-severity columns.
		rowBg := bgColor
		if i%2 == 1 && bgColor == BgInfo {
			rowBg = ColorLightGray
		}

		// Maroto v2 wraps text across multiple lines within a cell when the
		// row is added via AddAutoRow (see below). Don't pre-truncate the
		// string — let the renderer break on word boundaries. Long unwrappable
		// single tokens (paths with no slashes, base64 blobs) still need a
		// hard cap so they don't overflow a single cell width; that's what
		// middleTruncate handles below.
		filePath := middleTruncate(f.Location.File, 80)

		lineStr := fmt.Sprintf("%d", f.Location.StartLine)

		desc := f.Description
		if desc == "" {
			desc = f.Name
		}

		qs := string(f.Properties.QuantumStatus)
		if qs == "" {
			qs = "unknown"
		}

		cellText := props.Text{
			Size:  7,
			Align: align.Center,
			Top:   1.5,
			Color: &props.BlackColor,
		}

		// Grid rebalance: Description gets 4/12 (was 3); Quantum Status
		// gets 1/12 (was 2 — labels are 5-10 chars, never need 2 columns).
		// Total: 1 sev + 3 file + 1 line + 2 name + 4 desc + 1 quantum = 12.
		// AddAutoRow lets maroto grow the row vertically when wrapped text
		// in any cell exceeds the natural single-line height.
		m.AddAutoRow(
			col.New(1).Add(text.New(sevLabel, props.Text{
				Size:  7,
				Style: fontstyle.Bold,
				Align: align.Center,
				Top:   1.5,
				Color: sevColor,
			})).WithStyle(&props.Cell{
				BackgroundColor: bgColor,
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(3).Add(text.New(filePath, props.Text{
				Size:  7,
				Align: align.Left,
				Top:   1.5,
				Left:  1,
				Color: &props.BlackColor,
			})).WithStyle(&props.Cell{
				BackgroundColor: rowBg,
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(1).Add(text.New(lineStr, cellText)).WithStyle(&props.Cell{
				BackgroundColor: rowBg,
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(2).Add(text.New(f.Name, props.Text{
				Size:  7,
				Align: align.Left,
				Top:   1.5,
				Left:  1,
				Color: &props.BlackColor,
			})).WithStyle(&props.Cell{
				BackgroundColor: rowBg,
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(4).Add(text.New(desc, props.Text{
				Size:  7,
				Align: align.Left,
				Top:   1.5,
				Left:  1,
				Color: &props.BlackColor,
			})).WithStyle(&props.Cell{
				BackgroundColor: rowBg,
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(1).Add(text.New(qs, props.Text{
				Size:  7,
				Align: align.Center,
				Top:   1.5,
				Color: quantumStatusColor(f.Properties.QuantumStatus),
			})).WithStyle(&props.Cell{
				BackgroundColor: rowBg,
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
		)
	}

	m.AddRow(6)
}

// quantumStatusColor maps a quantum status to its display color.
// Extracted from cli/internal/output/pdf.go.
func quantumStatusColor(qs types.QuantumStatus) *props.Color {
	switch qs {
	case types.QuantumVulnerable:
		return ColorCritical
	case types.QuantumSafe:
		return &props.Color{Red: 40, Green: 140, Blue: 40}
	case types.Broken:
		return &props.Color{Red: 140, Green: 20, Blue: 20}
	case types.QuantumUnknown:
		return ColorMedium
	default:
		return ColorInfo
	}
}

// middleTruncate shortens a long unwrappable string by replacing its middle
// with an ellipsis, preserving roughly equal head and tail context. Used for
// file paths and other slash-bearing tokens where both the leading directory
// context and the trailing filename are useful. Strings <= max are returned
// unchanged; very short max values (< 8) fall back to head-truncation.
func middleTruncate(s string, max int) string {
	if max < 8 {
		// Below 8 chars, ellipsis + tail isn't meaningful; head-truncate.
		runes := []rune(s)
		if len(runes) <= max {
			return s
		}
		return string(runes[:max])
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	// Reserve 3 runes for "..." then split remaining budget head/tail.
	keep := max - 3
	head := keep / 2
	tail := keep - head
	return string(runes[:head]) + "..." + string(runes[len(runes)-tail:])
}
