package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ANSI color codes
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
	boldRed = "\033[1;31m"
	boldYel = "\033[1;33m"
	boldGrn = "\033[1;32m"
	boldCyn = "\033[1;36m"
	boldWht = "\033[1;37m"
	orange  = "\033[38;5;208m"
	grey    = "\033[38;5;245m"
)

// colorEnabled returns true if output should use ANSI colors.
func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	// Check if the underlying writer is a terminal.
	// Cobra's OutOrStdout() may wrap os.Stdout, so also check stdout directly.
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			return true
		}
	}
	// Fallback: if no --output flag was used, we're likely writing to stdout.
	fi, err := os.Stdout.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		return true
	}
	return false
}

// TextWriter writes a human-readable text summary to the terminal.
type TextWriter struct{}

// Format returns the name of this output format.
func (w *TextWriter) Format() string { return "text" }

// WriteScanResult writes a colorized, human-readable summary of scan results.
func (w *TextWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	color := colorEnabled(wr)
	duration := result.EndTime.Sub(result.StartTime).Seconds()

	c := func(code, text string) string {
		if !color {
			return text
		}
		return code + text + reset
	}

	p := func(format string, a ...any) {
		fmt.Fprintf(wr, format+"\n", a...)
	}

	// Header
	p("")
	p("  %s", c(boldWht, fmt.Sprintf("CipherRadar v%s — Cryptography Bill of Materials Scanner", AppVersion)))
	p("")

	// Target
	p("  %s %s", c(grey, "Scanning:"), result.Target)

	// Language breakdown
	langCounts := countLanguages(result)
	if len(langCounts) > 0 {
		langParts := make([]string, 0, len(langCounts))
		for _, lc := range langCounts {
			langParts = append(langParts, fmt.Sprintf("%s (%d files)", lc.lang, lc.count))
		}
		p("  %s %s", c(grey, "Languages:"), strings.Join(langParts, ", "))
	}
	p("")

	// Per-pass stats
	passCounts := countByPass(result)
	cumulative := 0
	for _, pass := range result.PassesRun {
		cnt := passCounts[pass]
		cumulative += cnt
		label := passLabel(pass)
		if pass == 1 {
			p("  %s   %s  %s",
				c(cyan, fmt.Sprintf("Pass %d (%s):", pass, label)),
				c(boldWht, fmt.Sprintf("%d findings", cnt)),
				c(grey, fmt.Sprintf("[%.1fs]", duration*0.6)))
		} else {
			p("  %s   %s  %s",
				c(cyan, fmt.Sprintf("Pass %d (%s):", pass, label)),
				c(boldWht, fmt.Sprintf("+%d findings", cnt)),
				c(grey, fmt.Sprintf("[%.1fs]", duration*0.4)))
		}
	}
	p("")

	// Banner
	bannerText := fmt.Sprintf("  SCAN COMPLETE: %d findings in %.1fs", len(result.Findings), duration)
	bannerLine := strings.Repeat("═", len(bannerText)+2)
	p("  %s", c(boldYel, bannerLine))
	p("  %s", c(boldYel, bannerText))
	p("  %s", c(boldYel, bannerLine))
	p("")

	// Severity summary with color-coded rows
	sevCounts := map[types.Severity]int{}
	for _, f := range result.Findings {
		sevCounts[f.Severity]++
	}

	// Find a representative finding for each severity
	sevExamples := findSeverityExamples(result)

	printSevRow := func(sev types.Severity, label, colorCode string) {
		cnt := sevCounts[sev]
		if cnt == 0 {
			return
		}
		example := sevExamples[sev]
		desc := example.name
		loc := example.loc
		p("  %s  %s  %s  %s",
			c(colorCode, fmt.Sprintf("%-9s", label)),
			c(boldWht, fmt.Sprintf("%-5d", cnt)),
			c(white, fmt.Sprintf("%-28s", desc)),
			c(grey, loc))
	}

	printSevRow(types.SeverityCritical, "CRITICAL", boldRed)
	printSevRow(types.SeverityHigh, "HIGH", orange)
	printSevRow(types.SeverityMedium, "MEDIUM", yellow)
	printSevRow(types.SeverityLow, "LOW", dim)
	printSevRow(types.SeverityInfo, "INFO", grey)
	p("")

	// Quantum readiness
	totalFindings := len(result.Findings)
	qCounts := map[types.QuantumStatus]int{}
	for _, f := range result.Findings {
		qs := f.Properties.QuantumStatus
		if qs == "" {
			qs = types.QuantumUnknown
		}
		qCounts[qs]++
	}

	safeCount := qCounts[types.QuantumSafe]
	vulnCount := qCounts[types.QuantumVulnerable]
	if totalFindings > 0 {
		readiness := float64(safeCount) / float64(totalFindings) * 100
		readinessColor := boldRed
		if readiness >= 80 {
			readinessColor = boldGrn
		} else if readiness >= 50 {
			readinessColor = boldYel
		}
		p("  %s %s  %s",
			c(grey, "Quantum Readiness:"),
			c(readinessColor, fmt.Sprintf("%.0f%%", readiness)),
			c(grey, fmt.Sprintf("(%d of %d findings are quantum-safe)", safeCount, totalFindings)))

		if vulnCount > 0 {
			p("  %s %s",
				c(grey, "Quantum Vulnerable:"),
				c(red, fmt.Sprintf("%d findings", vulnCount)))
		}
	}

	if len(result.Errors) > 0 {
		p("")
		p("  %s %d", c(red, "Errors:"), len(result.Errors))
		for _, e := range result.Errors {
			p("    %s: %s", c(grey, e.File), e.Message)
		}
	}

	p("")
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

type langCount struct {
	lang  string
	count int
}

func countLanguages(result *types.ScanResult) []langCount {
	extToLang := map[string]string{
		".py": "Python", ".java": "Java", ".js": "JavaScript", ".ts": "TypeScript",
		".go": "Go", ".kt": "Kotlin", ".cs": "C#", ".php": "PHP",
		".rb": "Ruby", ".rs": "Rust", ".swift": "Swift", ".dart": "Dart",
		".cpp": "C++", ".c": "C", ".h": "C/C++",
		".conf": "Config", ".cnf": "Config", ".yml": "Config", ".yaml": "Config",
		".properties": "Config", ".env": "Config",
	}

	langFiles := map[string]map[string]bool{}
	for _, f := range result.Findings {
		ext := strings.ToLower(filepath.Ext(f.Location.File))
		lang := extToLang[ext]
		if lang == "" {
			lang = "Other"
		}
		if langFiles[lang] == nil {
			langFiles[lang] = map[string]bool{}
		}
		langFiles[lang][f.Location.File] = true
	}

	counts := make([]langCount, 0, len(langFiles))
	for lang, files := range langFiles {
		counts = append(counts, langCount{lang, len(files)})
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].count > counts[j].count
	})

	// Limit to top 6
	if len(counts) > 6 {
		counts = counts[:6]
	}
	return counts
}

func countByPass(result *types.ScanResult) map[int]int {
	counts := map[int]int{}
	for _, f := range result.Findings {
		counts[f.Pass]++
	}
	return counts
}

func passLabel(pass int) string {
	switch pass {
	case 1:
		return "AST"
	case 2:
		return "Taint"
	default:
		return "Scan"
	}
}

type sevExample struct {
	name string
	loc  string
}

func findSeverityExamples(result *types.ScanResult) map[types.Severity]sevExample {
	examples := map[types.Severity]sevExample{}
	for _, f := range result.Findings {
		if _, exists := examples[f.Severity]; !exists {
			loc := fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine)
			name := f.Name
			if f.Properties.QuantumStatus == types.QuantumVulnerable {
				name += " (quantum-vuln)"
			}
			examples[f.Severity] = sevExample{name: name, loc: loc}
		}
	}
	return examples
}
