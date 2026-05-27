package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Color palette shared across all PDF sections. Exact values mirror the
// pre-split cli/internal/output/pdf.go (lines 44-61 in v0.2.0-rc.5).
var (
	ColorCritical  = &props.Color{Red: 180, Green: 30, Blue: 30}
	ColorHigh      = &props.Color{Red: 220, Green: 120, Blue: 20}
	ColorMedium    = &props.Color{Red: 180, Green: 160, Blue: 20}
	ColorLow       = &props.Color{Red: 40, Green: 100, Blue: 180}
	ColorInfo      = &props.Color{Red: 120, Green: 120, Blue: 120}
	ColorWhite     = &props.Color{Red: 255, Green: 255, Blue: 255}
	ColorDarkGray  = &props.Color{Red: 60, Green: 60, Blue: 60}
	ColorLightGray = &props.Color{Red: 240, Green: 240, Blue: 240}
	ColorHeaderBg  = &props.Color{Red: 35, Green: 45, Blue: 75}
	ColorPass      = &props.Color{Red: 40, Green: 140, Blue: 40}

	BgCritical = &props.Color{Red: 255, Green: 220, Blue: 220}
	BgHigh     = &props.Color{Red: 255, Green: 235, Blue: 210}
	BgMedium   = &props.Color{Red: 255, Green: 250, Blue: 210}
	BgLow      = &props.Color{Red: 220, Green: 235, Blue: 255}
	BgInfo     = &props.Color{Red: 240, Green: 240, Blue: 240}
)

// SeverityOrder returns a sort key so SeverityCritical = 0 (sorts first).
func SeverityOrder(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 0
	case types.SeverityHigh:
		return 1
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 3
	default:
		return 4
	}
}

// SeverityColor returns the foreground color for a severity badge.
func SeverityColor(s types.Severity) *props.Color {
	switch s {
	case types.SeverityCritical:
		return ColorCritical
	case types.SeverityHigh:
		return ColorHigh
	case types.SeverityMedium:
		return ColorMedium
	case types.SeverityLow:
		return ColorLow
	default:
		return ColorInfo
	}
}

// SeverityBgColor returns the background color for a severity row/badge.
func SeverityBgColor(s types.Severity) *props.Color {
	switch s {
	case types.SeverityCritical:
		return BgCritical
	case types.SeverityHigh:
		return BgHigh
	case types.SeverityMedium:
		return BgMedium
	case types.SeverityLow:
		return BgLow
	default:
		return BgInfo
	}
}
