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

// writerRegistry holds extra format constructors registered via RegisterWriter.
// It is populated at init time by sub-packages (e.g. output/pdf) that would
// create an import cycle if imported directly from this file.
var writerRegistry = map[string]func() Writer{}

// RegisterWriter registers a constructor for a named format. Call from an
// init() in the format's package after importing this package.
// Panics if the format name is already registered (programming error).
func RegisterWriter(format string, ctor func() Writer) {
	if _, dup := writerRegistry[format]; dup {
		panic("output: duplicate writer registration for format " + format)
	}
	writerRegistry[format] = ctor
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
	case "table":
		return &TableWriter{}, nil
	case "sonarqube-generic":
		return &SonarQubeWriter{}, nil
	default:
		if ctor, ok := writerRegistry[format]; ok {
			return ctor(), nil
		}
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
