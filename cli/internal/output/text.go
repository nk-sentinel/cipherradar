package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// TextWriter writes a human-readable text summary to the terminal.
type TextWriter struct{}

// Format returns the name of this output format.
func (w *TextWriter) Format() string { return "text" }

// WriteScanResult writes a human-readable summary of scan results to the given writer.
func (w *TextWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	duration := result.EndTime.Sub(result.StartTime).Seconds()

	p := func(format string, a ...any) {
		fmt.Fprintf(wr, format+"\n", a...)
	}

	p("CipherRadar Scan Results")
	p("========================")
	p("Target:  %s", result.Target)
	p("Files:   %d scanned", result.FilesScanned)
	p("Time:    %.2fs", duration)

	passStrs := make([]string, 0, len(result.PassesRun))
	for _, pass := range result.PassesRun {
		passStrs = append(passStrs, fmt.Sprintf("%d", pass))
	}
	p("Passes:  %s", strings.Join(passStrs, ","))

	p("")

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

	p("Findings: %d", len(result.Findings))
	p("  CRITICAL: %d", sevCounts[types.SeverityCritical])
	p("  HIGH:     %d", sevCounts[types.SeverityHigh])
	p("  MEDIUM:   %d", sevCounts[types.SeverityMedium])
	p("  LOW:      %d", sevCounts[types.SeverityLow])
	p("  INFO:     %d", sevCounts[types.SeverityInfo])

	p("")

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

	p("Quantum Status:")
	p("  Vulnerable: %d", qCounts[types.QuantumVulnerable])
	p("  Safe:       %d", qCounts[types.QuantumSafe])
	p("  Unknown:    %d", qCounts[types.QuantumUnknown])
	p("  Broken:     %d", qCounts[types.Broken])

	if len(result.Findings) > 0 {
		p("")
		p("Top Findings:")

		// Sort by severity priority: critical > high > medium > low > info.
		sorted := make([]types.Finding, len(result.Findings))
		copy(sorted, result.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return severityOrder(sorted[i].Severity) < severityOrder(sorted[j].Severity)
		})

		limit := 10
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for _, f := range sorted[:limit] {
			loc := fmt.Sprintf("%s:%d:%d", f.Location.File, f.Location.StartLine, f.Location.StartCol)
			sev := strings.ToUpper(string(f.Severity))
			desc := f.Description
			if desc == "" {
				desc = f.Name
			}
			p("  %-9s %-25s %s — %s", sev, loc, f.Name, desc)
		}
	}

	if len(result.Errors) > 0 {
		p("")
		p("Errors: %d", len(result.Errors))
		for _, e := range result.Errors {
			p("  %s: %s", e.File, e.Message)
		}
	}

	return nil
}

// severityOrder returns a numeric order for sorting (lower = more severe).
func severityOrder(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 0
	case types.SeverityHigh:
		return 1
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 3
	case types.SeverityInfo:
		return 4
	default:
		return 5
	}
}
