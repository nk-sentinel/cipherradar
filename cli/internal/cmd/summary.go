package cmd

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ResolvedOutput is one resolved sink — a destination path with its format and final size.
type ResolvedOutput struct {
	Path   string
	Format string
	Size   int64 // bytes, post-write
}

// emitFinalSummary writes the always-on scan summary to wr. Suppressed when
// quiet is true OR when stdout is already receiving text-format output (the
// common TTY default — the text writer already includes a summary).
//
// Duplication-avoidance rule:
//   - stdoutFormat == "text" AND no -o paths → suppress (already on stdout)
//   - otherwise → emit summary line + one "wrote" line per resolved path
func emitFinalSummary(wr io.Writer, result *types.ScanResult, paths []ResolvedOutput, stdoutFormat string, quiet bool) {
	if quiet {
		return
	}
	if stdoutFormat == "text" && len(paths) == 0 {
		return
	}
	sevCounts := map[types.Severity]int{}
	for _, f := range result.Findings {
		sevCounts[f.Severity]++
	}
	duration := result.EndTime.Sub(result.StartTime)
	fmt.Fprintf(wr, "[scan] complete in %s — %d findings (%d CRIT / %d HIGH / %d MED / %d LOW / %d INFO)\n",
		duration.Round(10_000_000),
		len(result.Findings),
		sevCounts[types.SeverityCritical], sevCounts[types.SeverityHigh],
		sevCounts[types.SeverityMedium], sevCounts[types.SeverityLow],
		sevCounts[types.SeverityInfo])
	for _, p := range paths {
		abs, err := filepath.Abs(p.Path)
		if err != nil {
			abs = p.Path
		}
		fmt.Fprintf(wr, "[scan] wrote %s (%s, %s)\n", abs, p.Format, humanSize(p.Size))
	}
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
