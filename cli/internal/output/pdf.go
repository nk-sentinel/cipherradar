package output

import (
	"fmt"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// PDFWriter generates a detailed PDF report from scan results.
type PDFWriter struct{}

// Format returns the name of this output format.
func (w *PDFWriter) Format() string { return "pdf" }

// WriteScanResult generates a PDF report from the scan results and writes it to the given writer.
func (w *PDFWriter) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	// TODO: Generate PDF using maroto — findings table, severity chart, quantum summary
	return fmt.Errorf("pdf output not yet implemented")
}
