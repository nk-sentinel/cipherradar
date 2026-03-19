package dart

import (
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// QuantumInfo holds the quantum readiness classification for a crypto algorithm.
// It delegates to the shared quantum package.
type QuantumInfo struct {
	Status         types.QuantumStatus
	NistLevel      int    // 0 if not applicable
	Recommendation string // migration guidance
}

// GetQuantumInfo returns the quantum readiness info for a given algorithm family.
// The algorithm family name is matched case-insensitively.
// Returns QuantumUnknown status if the algorithm is not recognized.
func GetQuantumInfo(algorithmFamily string) QuantumInfo {
	info := quantum.GetInfo(algorithmFamily)
	return QuantumInfo{
		Status:         info.Status,
		NistLevel:      info.NistLevel,
		Recommendation: info.Recommendation,
	}
}
