package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/core"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addCompliance renders one tile per compliance framework that was
// evaluated during the scan. No-op when no compliance results are present
// on the ScanResult.
//
// Currently a stub — types.ScanResult does not yet carry a stable
// ComplianceResults field. The renderer call site is wired so a future
// framework integration (per ADR-023) only needs to add the data shape
// and fill in this function. Until then, this is intentionally empty.
func addCompliance(m core.Maroto, result *types.ScanResult) {
	_ = m
	_ = result
}
