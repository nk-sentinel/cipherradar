package output

import (
	"encoding/json"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// CycloneDXJSONWriter writes scan results as CycloneDX 1.7 JSON.
type CycloneDXJSONWriter struct{}

// Format returns the name of this output format.
func (w *CycloneDXJSONWriter) Format() string { return "cyclonedx-json" }

// WriteScanResult writes the scan results to the given writer as CycloneDX 1.7 JSON.
func (w *CycloneDXJSONWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	bom := ConvertScanResult(result)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return err
	}

	// Append trailing newline for well-formed output.
	data = append(data, '\n')

	_, err = wr.Write(data)
	return err
}
