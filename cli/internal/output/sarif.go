package output

import (
	"fmt"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// SARIFWriter writes scan results as SARIF 2.1 JSON.
type SARIFWriter struct{}

// Format returns the name of this output format.
func (w *SARIFWriter) Format() string { return "sarif" }

// WriteScanResult writes the scan results to the given writer as SARIF 2.1 JSON.
func (w *SARIFWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	// TODO: Convert types.ScanResult → SARIF 2.1 JSON
	return fmt.Errorf("sarif output not yet implemented")
}
