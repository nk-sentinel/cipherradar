package output

import (
	"fmt"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Writer serializes scan results to a specific format.
type Writer interface {
	// WriteScanResult writes the scan results to the given writer.
	WriteScanResult(w io.Writer, result *types.ScanResult) error

	// Format returns the name of this output format.
	Format() string
}

// WriterFactory returns a Writer for the given format name.
// Supported formats: "cyclonedx-json", "sarif", "text", "pdf", "sonarqube-generic".
func WriterFactory(format string) (Writer, error) {
	switch format {
	case "cyclonedx-json":
		return &CycloneDXJSONWriter{}, nil
	case "sarif":
		return &SARIFWriter{}, nil
	case "text":
		return &TextWriter{}, nil
	case "pdf":
		return &PDFWriter{}, nil
	case "sonarqube-generic":
		return &SonarQubeWriter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
