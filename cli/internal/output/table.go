package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// TableWriter emits one row per finding — the row-level view users
// reached for when "text" turned out to be a dashboard summary. Columns
// are whitespace-aligned via text/tabwriter so the output is both
// human-readable and pipe-friendly (awk/cut friendly on the tab).
type TableWriter struct{}

// Format returns the registered name of this writer.
func (*TableWriter) Format() string { return "table" }

// WriteScanResult writes findings as an aligned table. Findings are
// sorted by severity (critical → info) then by location so the most
// interesting rows surface first. An empty finding set produces a single
// "no findings" line so callers can still tell the scan ran.
func (*TableWriter) WriteScanResult(w io.Writer, result *types.ScanResult) error {
	if result == nil || len(result.Findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}

	rows := make([]types.Finding, len(result.Findings))
	copy(rows, result.Findings)
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := severityRank(rows[i].Severity), severityRank(rows[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if rows[i].Location.File != rows[j].Location.File {
			return rows[i].Location.File < rows[j].Location.File
		}
		return rows[i].Location.StartLine < rows[j].Location.StartLine
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tLOCATION\tNAME")
	for _, f := range rows {
		loc := fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine)
		name := f.Name
		if name == "" {
			name = strings.TrimSpace(f.Description)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			string(f.Severity), f.RuleID, loc, name)
	}
	return tw.Flush()
}

// severityRank maps severity strings to a comparable rank; unknown
// values fall below info so they never float above a real finding.
func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	case types.SeverityInfo:
		return 0
	}
	return -1
}
