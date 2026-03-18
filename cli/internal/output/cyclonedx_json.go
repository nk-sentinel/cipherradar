package output

import (
	"fmt"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// CycloneDXJSONWriter writes scan results as CycloneDX 1.7 JSON.
type CycloneDXJSONWriter struct{}

// Format returns the name of this output format.
func (w *CycloneDXJSONWriter) Format() string { return "cyclonedx-json" }

// WriteScanResult writes the scan results to the given writer as CycloneDX 1.7 JSON.
func (w *CycloneDXJSONWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	// TODO: Convert types.ScanResult → CycloneDX 1.7 BOM with cryptoProperties
	// Will use cyclonedx-go for the envelope + internal/cyclonedx17 for crypto fields
	return fmt.Errorf("cyclonedx-json output not yet implemented")
}
