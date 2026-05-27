package pdf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addQuantum renders the quantum readiness section (preserved from pdf.go
// addQuantumReadinessSection) followed by a new Quantum Migration Backlog
// table introduced in Option D.
func addQuantum(m core.Maroto, result *types.ScanResult) {
	// ─── Preserved: existing quantum readiness section ───

	// Separator.
	m.AddRows(line.NewRow(2, props.Line{
		Color:     ColorLightGray,
		Thickness: 0.3,
	}))

	m.AddRow(4)

	// Section header.
	m.AddRow(10,
		text.NewCol(12, "Quantum Readiness Summary", props.Text{
			Size:  14,
			Style: fontstyle.Bold,
			Color: ColorHeaderBg,
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
		// Skip not-applicable findings (libraries, certs) — they don't belong in
		// the migration recommendations table.
		if f.Properties.QuantumStatus == types.QuantumNotApplicable {
			continue
		}

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
		BackgroundColor: ColorHeaderBg,
	}
	headerText := props.Text{
		Size:  8,
		Style: fontstyle.Bold,
		Align: align.Center,
		Top:   2,
		Color: ColorWhite,
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
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(3).Add(text.New(names, cellText)).WithStyle(&props.Cell{
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
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
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
			col.New(5).Add(text.New(recommendation, cellText)).WithStyle(&props.Cell{
				BorderType:      border.Full,
				BorderColor:     ColorLightGray,
				BorderThickness: 0.1,
			}),
		)
	}

	m.AddRow(6)

	// ─── New: migration backlog table ───
	addQuantumMigrationBacklog(m, result)
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

// BacklogEntry summarizes a vulnerable algorithm awaiting migration.
type BacklogEntry struct {
	Algorithm      string
	Count          int
	Status         types.QuantumStatus
	Recommendation string
	Examples       []string // up to 3 file:line locations
}

// buildMigrationBacklog returns the top N vulnerable / broken algorithm
// families in the scan, sorted by count desc.
func buildMigrationBacklog(result *types.ScanResult, top int) []BacklogEntry {
	groups := map[string]*BacklogEntry{}
	for _, f := range result.Findings {
		qs := f.Properties.QuantumStatus
		if qs != types.QuantumVulnerable && qs != types.Broken {
			continue
		}
		key := f.Properties.AlgorithmFamily
		if key == "" {
			key = f.Name
		}
		e, ok := groups[key]
		if !ok {
			info := quantum.GetInfo(key)
			e = &BacklogEntry{
				Algorithm: key, Status: qs, Recommendation: info.Recommendation,
			}
			groups[key] = e
		}
		e.Count++
		if len(e.Examples) < 3 {
			e.Examples = append(e.Examples, fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine))
		}
	}
	out := make([]BacklogEntry, 0, len(groups))
	for _, e := range groups {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Algorithm < out[j].Algorithm
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

func addQuantumMigrationBacklog(m core.Maroto, result *types.ScanResult) {
	backlog := buildMigrationBacklog(result, 10)
	if len(backlog) == 0 {
		return
	}

	m.AddRow(10, text.NewCol(12, "Quantum Migration Backlog", props.Text{
		Size: 14, Style: fontstyle.Bold, Color: ColorCritical,
	}))
	m.AddRow(4)

	header := props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center, Top: 2, Color: ColorWhite}
	cellH := &props.Cell{BackgroundColor: ColorHeaderBg}
	m.AddRow(8,
		col.New(2).Add(text.New("Algorithm", header)).WithStyle(cellH),
		col.New(1).Add(text.New("Count", header)).WithStyle(cellH),
		col.New(2).Add(text.New("Status", header)).WithStyle(cellH),
		col.New(4).Add(text.New("Recommendation", header)).WithStyle(cellH),
		col.New(3).Add(text.New("Examples (top 3)", header)).WithStyle(cellH),
	)

	cell := props.Text{Size: 7, Top: 1.5, Color: &props.BlackColor, Align: align.Left, Left: 1}
	rowStyle := &props.Cell{BackgroundColor: BgCritical, BorderType: border.Full, BorderColor: ColorLightGray, BorderThickness: 0.1}
	for _, e := range backlog {
		examples := ""
		for i, ex := range e.Examples {
			if i > 0 {
				examples += "; "
			}
			examples += ex
		}
		m.AddRow(7,
			col.New(2).Add(text.New(e.Algorithm, cell)).WithStyle(rowStyle),
			col.New(1).Add(text.New(fmt.Sprintf("%d", e.Count), props.Text{Size: 7, Top: 1.5, Align: align.Center, Color: &props.BlackColor})).WithStyle(rowStyle),
			col.New(2).Add(text.New(string(e.Status), cell)).WithStyle(rowStyle),
			col.New(4).Add(text.New(e.Recommendation, cell)).WithStyle(rowStyle),
			col.New(3).Add(text.New(examples, cell)).WithStyle(rowStyle),
		)
	}
	m.AddRow(6)
}
