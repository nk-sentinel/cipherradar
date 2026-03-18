package output

import (
	"fmt"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// TextWriter writes a human-readable text summary to the terminal.
type TextWriter struct{}

// Format returns the name of this output format.
func (w *TextWriter) Format() string { return "text" }

// WriteScanResult writes a human-readable summary of scan results to the given writer.
func (w *TextWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	// TODO: Write human-readable summary: finding count, severity breakdown, quantum status
	return fmt.Errorf("text output not yet implemented")
}
