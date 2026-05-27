package pdf

import (
	"fmt"
	"strings"

	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addCover renders the report cover: title, subtitle, target/duration/version metadata.
// Extracted from cli/internal/output/pdf.go addCoverSection.
func addCover(m core.Maroto, result *types.ScanResult) {
	// Spacer.
	m.AddRow(15)

	// Title.
	m.AddRow(14,
		text.NewCol(12, "CipherRadar CBOM Scan Report", props.Text{
			Size:  20,
			Style: fontstyle.Bold,
			Align: align.Center,
			Color: ColorHeaderBg,
		}),
	)

	// Subtitle.
	m.AddRow(7,
		text.NewCol(12, "Cryptographic Bill of Materials Analysis", props.Text{
			Size:  11,
			Align: align.Center,
			Color: ColorInfo,
		}),
	)

	// Separator line.
	m.AddRows(line.NewRow(2, props.Line{
		Color:     ColorHeaderBg,
		Thickness: 0.5,
	}))

	m.AddRow(6)

	// Scan metadata.
	duration := result.EndTime.Sub(result.StartTime).Seconds()
	scanDate := result.StartTime.Format("2006-01-02 15:04:05 MST")

	passStrs := make([]string, 0, len(result.PassesRun))
	for _, pass := range result.PassesRun {
		passStrs = append(passStrs, fmt.Sprintf("%d", pass))
	}

	metaRows := []struct {
		label string
		value string
	}{
		{"Target", result.Target},
		{"Scan Date", scanDate},
		{"Duration", fmt.Sprintf("%.2f seconds", duration)},
		{"Files Scanned", fmt.Sprintf("%d", result.FilesScanned)},
		{"Passes Run", strings.Join(passStrs, ", ")},
		{"Total Findings", fmt.Sprintf("%d", len(result.Findings))},
	}

	for _, meta := range metaRows {
		m.AddRow(6,
			text.NewCol(3, meta.label, props.Text{
				Size:  9,
				Style: fontstyle.Bold,
				Align: align.Right,
				Right: 4,
				Color: ColorDarkGray,
			}),
			text.NewCol(9, meta.value, props.Text{
				Size:  9,
				Left:  2,
				Color: &props.BlackColor,
			}),
		)
	}

	m.AddRow(6)
}
