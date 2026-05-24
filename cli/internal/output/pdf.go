package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// PDFWriter generates a detailed PDF report from scan results.
type PDFWriter struct{}

// Format returns the name of this output format.
func (w *PDFWriter) Format() string { return "pdf" }

// WriteScanResult generates a PDF report from the scan results and writes it to the given writer.
func (w *PDFWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	doc, err := generatePDF(result)
	if err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	bytes := doc.GetBytes()
	if _, err := wr.Write(bytes); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}

	return nil
}

// Color definitions for severity levels and report styling.
var (
	colorCritical  = &props.Color{Red: 180, Green: 30, Blue: 30}
	colorHigh      = &props.Color{Red: 220, Green: 120, Blue: 20}
	colorMedium    = &props.Color{Red: 180, Green: 160, Blue: 20}
	colorLow       = &props.Color{Red: 40, Green: 100, Blue: 180}
	colorInfo      = &props.Color{Red: 120, Green: 120, Blue: 120}
	colorWhite     = &props.Color{Red: 255, Green: 255, Blue: 255}
	colorDarkGray  = &props.Color{Red: 60, Green: 60, Blue: 60}
	colorLightGray = &props.Color{Red: 240, Green: 240, Blue: 240}
	colorHeaderBg  = &props.Color{Red: 35, Green: 45, Blue: 75}

	bgCritical = &props.Color{Red: 255, Green: 220, Blue: 220}
	bgHigh     = &props.Color{Red: 255, Green: 235, Blue: 210}
	bgMedium   = &props.Color{Red: 255, Green: 250, Blue: 210}
	bgLow      = &props.Color{Red: 220, Green: 235, Blue: 255}
	bgInfo     = &props.Color{Red: 240, Green: 240, Blue: 240}
)

// generatePDF creates the full PDF report document from scan results.
func generatePDF(result *types.ScanResult) (core.Document, error) {
	cfg := config.NewBuilder().
		WithPageNumber(props.PageNumber{
			Pattern: "Page {current} of {total}",
			Place:   props.RightBottom,
			Size:    8,
			Color:   colorInfo,
		}).
		WithLeftMargin(10).
		WithTopMargin(15).
		WithRightMargin(10).
		WithBottomMargin(15).
		WithCreator("CipherRadar", true).
		WithTitle("CipherRadar CBOM Scan Report", true).
		Build()

	m := maroto.New(cfg)

	addCoverSection(m, result)
	addSummarySection(m, result)

	if len(result.Findings) > 0 {
		addFindingsTable(m, result)
		addQuantumReadinessSection(m, result)
	}

	addFooterNote(m)

	return m.Generate()
}

// addCoverSection adds the report title and scan metadata.
func addCoverSection(m core.Maroto, result *types.ScanResult) {
	// Spacer.
	m.AddRow(15)

	// Title.
	m.AddRow(14,
		text.NewCol(12, "CipherRadar CBOM Scan Report", props.Text{
			Size:  20,
			Style: fontstyle.Bold,
			Align: align.Center,
			Color: colorHeaderBg,
		}),
	)

	// Subtitle.
	m.AddRow(7,
		text.NewCol(12, "Cryptographic Bill of Materials Analysis", props.Text{
			Size:  11,
			Align: align.Center,
			Color: colorInfo,
		}),
	)

	// Separator line.
	m.AddRows(line.NewRow(2, props.Line{
		Color:     colorHeaderBg,
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
				Color: colorDarkGray,
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

// addSummarySection adds the severity and quantum status summary boxes.
func addSummarySection(m core.Maroto, result *types.ScanResult) {
	// Count findings by severity.
	sevCounts := map[types.Severity]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     0,
		types.SeverityMedium:   0,
		types.SeverityLow:      0,
		types.SeverityInfo:     0,
	}
	for _, f := range result.Findings {
		sevCounts[f.Severity]++
	}

	// Count findings by quantum status.
	qCounts := map[types.QuantumStatus]int{
		types.QuantumVulnerable: 0,
		types.QuantumSafe:       0,
		types.QuantumUnknown:    0,
		types.Broken:            0,
	}
	for _, f := range result.Findings {
		qs := f.Properties.QuantumStatus
		if qs == "" {
			qs = types.QuantumUnknown
		}
		qCounts[qs]++
	}

	// Severity Summary header.
	m.AddRow(8,
		text.NewCol(12, "Severity Breakdown", props.Text{
			Size:  12,
			Style: fontstyle.Bold,
			Color: colorHeaderBg,
		}),
	)

	// Severity row with colored badges.
	sevItems := []struct {
		label string
		count int
		color *props.Color
		bg    *props.Color
	}{
		{"CRITICAL", sevCounts[types.SeverityCritical], colorCritical, bgCritical},
		{"HIGH", sevCounts[types.SeverityHigh], colorHigh, bgHigh},
		{"MEDIUM", sevCounts[types.SeverityMedium], colorMedium, bgMedium},
		{"LOW", sevCounts[types.SeverityLow], colorLow, bgLow},
		{"INFO", sevCounts[types.SeverityInfo], colorInfo, bgInfo},
	}

	sevCols := make([]core.Col, 0, len(sevItems))
	for _, item := range sevItems {
		label := fmt.Sprintf("%s: %d", item.label, item.count)
		c := col.New(2).Add(
			text.New(label, props.Text{
				Size:  9,
				Style: fontstyle.Bold,
				Align: align.Center,
				Top:   2,
				Color: item.color,
			}),
		).WithStyle(&props.Cell{
			BackgroundColor: item.bg,
			BorderType:      border.Full,
			BorderColor:     item.color,
			BorderThickness: 0.3,
		})
		sevCols = append(sevCols, c)
	}
	// Add a spacer col to fill the remaining grid space.
	sevCols = append(sevCols, col.New(2))
	m.AddRow(10, sevCols...)

	m.AddRow(6)

	// Quantum Status header.
	m.AddRow(8,
		text.NewCol(12, "Quantum Readiness Overview", props.Text{
			Size:  12,
			Style: fontstyle.Bold,
			Color: colorHeaderBg,
		}),
	)

	qItems := []struct {
		label string
		count int
		color *props.Color
	}{
		{"Vulnerable", qCounts[types.QuantumVulnerable], colorCritical},
		{"Safe", qCounts[types.QuantumSafe], &props.Color{Red: 40, Green: 140, Blue: 40}},
		{"Unknown", qCounts[types.QuantumUnknown], colorMedium},
		{"Broken", qCounts[types.Broken], &props.Color{Red: 140, Green: 20, Blue: 20}},
	}

	qCols := make([]core.Col, 0, len(qItems))
	for _, item := range qItems {
		label := fmt.Sprintf("%s: %d", item.label, item.count)
		qCols = append(qCols, text.NewCol(3, label, props.Text{
			Size:  9,
			Style: fontstyle.Bold,
			Align: align.Center,
			Top:   2,
			Color: item.color,
		}))
	}
	m.AddRow(8, qCols...)

	m.AddRow(4)

	// Separator.
	m.AddRows(line.NewRow(2, props.Line{
		Color:     colorLightGray,
		Thickness: 0.3,
	}))

	m.AddRow(4)
}

// addFindingsTable adds the detailed findings table.
func addFindingsTable(m core.Maroto, result *types.ScanResult) {
	// Section header.
	m.AddRow(10,
		text.NewCol(12, "Detailed Findings", props.Text{
			Size:  14,
			Style: fontstyle.Bold,
			Color: colorHeaderBg,
		}),
	)

	m.AddRow(3)

	// Table header row.
	headerStyle := &props.Cell{
		BackgroundColor: colorHeaderBg,
	}
	headerText := props.Text{
		Size:  8,
		Style: fontstyle.Bold,
		Align: align.Center,
		Top:   2,
		Color: colorWhite,
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
		return severityOrder(sorted[i].Severity) < severityOrder(sorted[j].Severity)
	})

	// Add a row for each finding.
	for i, f := range sorted {
		sevLabel := strings.ToUpper(string(f.Severity))
		sevColor := severityColor(f.Severity)
		bgColor := severityBgColor(f.Severity)

		// Alternate row shading for non-severity columns.
		rowBg := bgColor
		if i%2 == 1 && bgColor == bgInfo {
			rowBg = colorLightGray
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
				BorderColor:     colorLightGray,
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
				BorderColor:     colorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(1).Add(text.New(lineStr, cellText)).WithStyle(&props.Cell{
				BackgroundColor: rowBg,
				BorderType:      border.Full,
				BorderColor:     colorLightGray,
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
				BorderColor:     colorLightGray,
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
				BorderColor:     colorLightGray,
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
				BorderColor:     colorLightGray,
				BorderThickness: 0.1,
			}),
		)
	}

	m.AddRow(6)
}

// addQuantumReadinessSection adds the quantum readiness summary table with migration recommendations.
func addQuantumReadinessSection(m core.Maroto, result *types.ScanResult) {
	// Separator.
	m.AddRows(line.NewRow(2, props.Line{
		Color:     colorLightGray,
		Thickness: 0.3,
	}))

	m.AddRow(4)

	// Section header.
	m.AddRow(10,
		text.NewCol(12, "Quantum Readiness Summary", props.Text{
			Size:  14,
			Style: fontstyle.Bold,
			Color: colorHeaderBg,
		}),
	)

	m.AddRow(3)

	// Collect unique algorithm families and their quantum status.
	type algoInfo struct {
		family string
		status types.QuantumStatus
		names  []string
	}
	familyMap := make(map[string]*algoInfo)

	for _, f := range result.Findings {
		family := f.Properties.AlgorithmFamily
		if family == "" {
			family = f.Name
		}
		key := strings.ToLower(family)

		if existing, ok := familyMap[key]; ok {
			// Collect unique names.
			found := false
			for _, n := range existing.names {
				if n == f.Name {
					found = true
					break
				}
			}
			if !found {
				existing.names = append(existing.names, f.Name)
			}
			// Keep the worst quantum status.
			if quantumStatusPriority(f.Properties.QuantumStatus) < quantumStatusPriority(existing.status) {
				existing.status = f.Properties.QuantumStatus
			}
		} else {
			qs := f.Properties.QuantumStatus
			if qs == "" {
				qs = types.QuantumUnknown
			}
			familyMap[key] = &algoInfo{
				family: family,
				status: qs,
				names:  []string{f.Name},
			}
		}
	}

	// Sort families by quantum status priority (worst first).
	families := make([]*algoInfo, 0, len(familyMap))
	for _, info := range familyMap {
		families = append(families, info)
	}
	sort.Slice(families, func(i, j int) bool {
		pi := quantumStatusPriority(families[i].status)
		pj := quantumStatusPriority(families[j].status)
		if pi != pj {
			return pi < pj
		}
		return families[i].family < families[j].family
	})

	// Table header.
	headerStyle := &props.Cell{
		BackgroundColor: colorHeaderBg,
	}
	headerText := props.Text{
		Size:  8,
		Style: fontstyle.Bold,
		Align: align.Center,
		Top:   2,
		Color: colorWhite,
	}

	m.AddRow(8,
		col.New(2).Add(text.New("Algorithm Family", headerText)).WithStyle(headerStyle),
		col.New(3).Add(text.New("Detected Assets", headerText)).WithStyle(headerStyle),
		col.New(2).Add(text.New("Quantum Status", headerText)).WithStyle(headerStyle),
		col.New(5).Add(text.New("Recommendation", headerText)).WithStyle(headerStyle),
	)

	for _, info := range families {
		// Maroto v2 wraps the comma-joined list naturally on word boundaries
		// in the 3/12 cell. Don't pre-truncate.
		names := strings.Join(info.names, ", ")

		statusLabel := string(info.status)
		if statusLabel == "" {
			statusLabel = "unknown"
		}

		recommendation := quantumRecommendation(info.family, info.status)

		cellText := props.Text{
			Size:  7,
			Align: align.Left,
			Top:   1.5,
			Left:  1,
			Color: &props.BlackColor,
		}

		m.AddAutoRow(
			col.New(2).Add(text.New(info.family, props.Text{
				Size:  7,
				Style: fontstyle.Bold,
				Align: align.Left,
				Top:   1.5,
				Left:  1,
				Color: &props.BlackColor,
			})).WithStyle(&props.Cell{
				BorderType:      border.Full,
				BorderColor:     colorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(3).Add(text.New(names, cellText)).WithStyle(&props.Cell{
				BorderType:      border.Full,
				BorderColor:     colorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(2).Add(text.New(statusLabel, props.Text{
				Size:  7,
				Style: fontstyle.Bold,
				Align: align.Center,
				Top:   1.5,
				Color: quantumStatusColor(info.status),
			})).WithStyle(&props.Cell{
				BorderType:      border.Full,
				BorderColor:     colorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(5).Add(text.New(recommendation, cellText)).WithStyle(&props.Cell{
				BorderType:      border.Full,
				BorderColor:     colorLightGray,
				BorderThickness: 0.1,
			}),
		)
	}

	m.AddRow(6)
}

// addFooterNote adds a disclaimer at the end of the report.
func addFooterNote(m core.Maroto) {
	m.AddRows(line.NewRow(2, props.Line{
		Color:     colorLightGray,
		Thickness: 0.3,
	}))

	m.AddRow(3)

	m.AddRow(5,
		text.NewCol(12, "Generated by CipherRadar v"+AppVersion+" — https://github.com/nk-sentinel/cipherradar", props.Text{
			Size:  7,
			Align: align.Center,
			Color: colorInfo,
		}),
	)

	m.AddRow(5,
		text.NewCol(12, "This report is for informational purposes. Verify findings before making compliance decisions.", props.Text{
			Size:  7,
			Align: align.Center,
			Color: colorInfo,
			Style: fontstyle.Italic,
		}),
	)
}

// severityColor returns the text color for a severity level.
func severityColor(s types.Severity) *props.Color {
	switch s {
	case types.SeverityCritical:
		return colorCritical
	case types.SeverityHigh:
		return colorHigh
	case types.SeverityMedium:
		return colorMedium
	case types.SeverityLow:
		return colorLow
	case types.SeverityInfo:
		return colorInfo
	default:
		return &props.BlackColor
	}
}

// severityBgColor returns the background color for a severity level.
func severityBgColor(s types.Severity) *props.Color {
	switch s {
	case types.SeverityCritical:
		return bgCritical
	case types.SeverityHigh:
		return bgHigh
	case types.SeverityMedium:
		return bgMedium
	case types.SeverityLow:
		return bgLow
	case types.SeverityInfo:
		return bgInfo
	default:
		return colorLightGray
	}
}

// quantumStatusColor returns the text color for a quantum status.
func quantumStatusColor(qs types.QuantumStatus) *props.Color {
	switch qs {
	case types.QuantumVulnerable:
		return colorCritical
	case types.QuantumSafe:
		return &props.Color{Red: 40, Green: 140, Blue: 40}
	case types.Broken:
		return &props.Color{Red: 140, Green: 20, Blue: 20}
	case types.QuantumUnknown:
		return colorMedium
	default:
		return colorInfo
	}
}

// quantumStatusPriority returns a numeric order for quantum status (lower = worse).
func quantumStatusPriority(qs types.QuantumStatus) int {
	switch qs {
	case types.Broken:
		return 0
	case types.QuantumVulnerable:
		return 1
	case types.QuantumUnknown:
		return 2
	case types.QuantumSafe:
		return 3
	default:
		return 4
	}
}

// quantumRecommendation returns a migration recommendation based on algorithm family and quantum status.
func quantumRecommendation(family string, status types.QuantumStatus) string {
	familyLower := strings.ToLower(family)

	if status == types.Broken {
		return "URGENT: Replace immediately. This algorithm is broken by classical attacks."
	}

	if status == types.QuantumSafe {
		return "No action needed. This algorithm is considered quantum-safe."
	}

	// Specific recommendations for known vulnerable algorithm families.
	switch {
	case strings.Contains(familyLower, "rsa"):
		return "Migrate to ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) for signatures."
	case strings.Contains(familyLower, "ecdsa") || strings.Contains(familyLower, "ecdh") || strings.Contains(familyLower, "ec"):
		return "Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key exchange."
	case strings.Contains(familyLower, "dsa"):
		return "Migrate to ML-DSA (FIPS 204) for digital signatures."
	case strings.Contains(familyLower, "dh") || strings.Contains(familyLower, "diffie"):
		return "Migrate to ML-KEM (FIPS 203) for key encapsulation."
	case strings.Contains(familyLower, "aes"):
		return "Increase key size to AES-256. AES-256 provides adequate quantum resistance."
	case strings.Contains(familyLower, "sha") && (strings.Contains(familyLower, "1") || strings.Contains(familyLower, "md")):
		return "Migrate to SHA-256 or SHA-3. Current algorithm is weak against classical attacks."
	case strings.Contains(familyLower, "md5") || strings.Contains(familyLower, "md4"):
		return "URGENT: Replace with SHA-256 or SHA-3. MD5 is broken by classical attacks."
	case strings.Contains(familyLower, "3des") || strings.Contains(familyLower, "des"):
		return "URGENT: Replace with AES-256-GCM. DES/3DES is no longer considered secure."
	}

	if status == types.QuantumVulnerable {
		return "Evaluate NIST PQC standards (FIPS 203/204/205) for quantum-safe replacement."
	}

	return "Review algorithm and assess quantum readiness based on latest NIST guidelines."
}

// middleTruncate shortens a long unwrappable string by replacing its middle
// with an ellipsis, preserving roughly equal head and tail context. Used for
// file paths and other slash-bearing tokens where both the leading directory
// context and the trailing filename are useful. Strings <= max are returned
// unchanged; very short max values (< 8) fall back to head-truncation.
//
// Examples (max=40):
//   cli/internal/scanner/python/python_scanner.go (45 chars) ->
//     cli/internal/scan…python/python_scanner.go (40 chars)
//   /a/very/long/path/here/with/many/segments/file.go ->
//     /a/very/long/path…segments/file.go
//
// Reserves three characters for the ellipsis "..." so that the result fits
// exactly within `max` runes (not bytes — caller passes a rune budget).
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
