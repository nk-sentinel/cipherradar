package pdf

import (
	"fmt"
	"path/filepath"
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

// extToLanguage maps common source-file extensions to a canonical language name.
// Extensions not listed here are silently ignored (not counted in Language breakdown).
var extToLanguage = map[string]string{
	".py":    "python",
	".go":    "go",
	".java":  "java",
	".js":    "javascript",
	".ts":    "typescript",
	".tsx":   "typescript",
	".jsx":   "javascript",
	".rb":    "ruby",
	".rs":    "rust",
	".c":     "c",
	".cc":    "c++",
	".cpp":   "c++",
	".cxx":   "c++",
	".cs":    "c#",
	".php":   "php",
	".swift": "swift",
	".kt":    "kotlin",
	".kts":   "kotlin",
	".scala": "scala",
	".ex":    "elixir",
	".exs":   "elixir",
	".r":     "r",
	".R":     "r",
	".m":     "objective-c",
	".mm":    "objective-c",
	".pl":    "perl",
	".sh":    "shell",
	".bash":  "shell",
	".zsh":   "shell",
	".ps1":   "powershell",
	".lua":   "lua",
	".dart":  "dart",
	".tf":    "terraform",
	".yaml":  "yaml",
	".yml":   "yaml",
	".json":  "json",
	".xml":   "xml",
}

// fileLanguage returns the canonical language name for a file path, or ""
// if the extension is not recognized.
func fileLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return extToLanguage[ext]
}

// KV is a string→int pair, used for sorted breakdowns like TopAlgorithms.
type KV struct {
	Key   string
	Value int
}

// SummaryStats holds the aggregated counts used by Option-D PDF sections.
type SummaryStats struct {
	Severity      map[types.Severity]int
	Quantum       map[types.QuantumStatus]int
	AssetType     map[string]int
	Primitive     map[string]int
	Language      map[string]int
	TopAlgorithms []KV
	Files         int
	Languages     int
}

// Aggregate computes a SummaryStats from a ScanResult.
// Language is inferred from each finding's Location.File extension;
// unrecognized extensions are omitted from the Language breakdown.
func Aggregate(result *types.ScanResult) SummaryStats {
	s := SummaryStats{
		Severity:  map[types.Severity]int{},
		Quantum:   map[types.QuantumStatus]int{},
		AssetType: map[string]int{},
		Primitive: map[string]int{},
		Language:  map[string]int{},
	}
	files := map[string]struct{}{}
	algorithms := map[string]int{}

	for _, f := range result.Findings {
		s.Severity[f.Severity]++

		if f.Properties.QuantumStatus != "" && f.Properties.QuantumStatus != types.QuantumNotApplicable {
			s.Quantum[f.Properties.QuantumStatus]++
		}

		s.AssetType[string(f.AssetType)]++

		if f.Properties.Primitive != "" {
			s.Primitive[f.Properties.Primitive]++
		}

		if f.Location.File != "" {
			files[f.Location.File] = struct{}{}
			if lang := fileLanguage(f.Location.File); lang != "" {
				s.Language[lang]++
			}
		}

		if f.Properties.AlgorithmFamily != "" {
			algorithms[f.Properties.AlgorithmFamily]++
		}
	}

	s.Files = len(files)
	s.Languages = len(s.Language)

	for k, v := range algorithms {
		s.TopAlgorithms = append(s.TopAlgorithms, KV{Key: k, Value: v})
	}
	sort.Slice(s.TopAlgorithms, func(i, j int) bool {
		if s.TopAlgorithms[i].Value != s.TopAlgorithms[j].Value {
			return s.TopAlgorithms[i].Value > s.TopAlgorithms[j].Value
		}
		return s.TopAlgorithms[i].Key < s.TopAlgorithms[j].Key
	})
	if len(s.TopAlgorithms) > 10 {
		s.TopAlgorithms = s.TopAlgorithms[:10]
	}

	return s
}

// addSummary renders the multi-section scan summary (severity, quantum, asset
// type, primitives, languages, top algorithms). All breakdowns from Option D.
func addSummary(m core.Maroto, result *types.ScanResult) {
	s := Aggregate(result)

	m.AddRow(10, text.NewCol(12, "Scan Summary", props.Text{
		Size: 14, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf(
		"Findings: %d   Files: %d   Languages: %d   Duration: %.2fs",
		len(result.Findings), s.Files, s.Languages,
		result.EndTime.Sub(result.StartTime).Seconds(),
	), props.Text{Size: 10, Color: ColorDarkGray})))
	m.AddRow(4)

	addSummaryRow(m, "Severity Breakdown", []labeledCount{
		{"CRITICAL", s.Severity[types.SeverityCritical], ColorCritical, BgCritical},
		{"HIGH", s.Severity[types.SeverityHigh], ColorHigh, BgHigh},
		{"MEDIUM", s.Severity[types.SeverityMedium], ColorMedium, BgMedium},
		{"LOW", s.Severity[types.SeverityLow], ColorLow, BgLow},
		{"INFO", s.Severity[types.SeverityInfo], ColorInfo, BgInfo},
	})

	addSummaryRow(m, "Quantum Readiness", []labeledCount{
		{"Vulnerable", s.Quantum[types.QuantumVulnerable], ColorCritical, BgCritical},
		{"Safe", s.Quantum[types.QuantumSafe], ColorPass, &props.Color{Red: 220, Green: 245, Blue: 220}},
		{"Unknown", s.Quantum[types.QuantumUnknown], ColorMedium, BgMedium},
		{"Broken", s.Quantum[types.Broken], &props.Color{Red: 140, Green: 20, Blue: 20}, BgCritical},
	})

	addBreakdownRow(m, "Asset Type", mapToSorted(s.AssetType))
	addBreakdownRow(m, "Cryptographic Primitives", mapToSorted(s.Primitive))
	if len(s.Language) > 0 {
		addBreakdownRow(m, "Languages", mapToSorted(s.Language))
	}
	if len(s.TopAlgorithms) > 0 {
		addBreakdownRow(m, "Top Algorithms", s.TopAlgorithms)
	}
	m.AddRow(4)
}

type labeledCount struct {
	label string
	count int
	color *props.Color
	bg    *props.Color
}

func addSummaryRow(m core.Maroto, header string, items []labeledCount) {
	m.AddRow(8, text.NewCol(12, header, props.Text{
		Size: 11, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	cols := make([]core.Col, 0, len(items)+1)
	for _, it := range items {
		label := fmt.Sprintf("%s: %d", it.label, it.count)
		c := col.New(2).Add(text.New(label, props.Text{
			Size: 9, Style: fontstyle.Bold, Align: align.Center, Top: 2, Color: it.color,
		})).WithStyle(&props.Cell{
			BackgroundColor: it.bg, BorderType: border.Full, BorderColor: it.color, BorderThickness: 0.3,
		})
		cols = append(cols, c)
	}
	used := len(items) * 2
	if used < 12 {
		cols = append(cols, col.New(12-used))
	}
	m.AddRow(10, cols...)
	m.AddRow(4)
}

func addBreakdownRow(m core.Maroto, header string, kvs []KV) {
	m.AddRow(8, text.NewCol(12, header, props.Text{
		Size: 11, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	parts := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		parts = append(parts, fmt.Sprintf("%s: %d", kv.Key, kv.Value))
	}
	m.AddRow(6, col.New(12).Add(text.New(strings.Join(parts, "   "), props.Text{
		Size: 9, Color: ColorDarkGray,
	})))
	m.AddRow(3)
}

func mapToSorted(m map[string]int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out
}
