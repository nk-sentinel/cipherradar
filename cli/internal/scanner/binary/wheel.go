package binary

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// WheelScanner handles Python wheel (.whl) and egg (.egg) files by extracting
// .py source files (scanned with the Python scanner) and .so/.pyd C extensions
// (scanned with the byte-pattern matcher).
type WheelScanner struct {
	pythonScanner scanner.Scanner
}

// NewWheelScanner creates a new Python wheel/egg scanner.
func NewWheelScanner() *WheelScanner {
	return &WheelScanner{
		pythonScanner: python.New(),
	}
}

// Name returns the scanner name.
func (s *WheelScanner) Name() string {
	return "wheel"
}

// Extensions returns the archive extensions this scanner handles.
func (s *WheelScanner) Extensions() []string {
	return []string{".whl", ".egg"}
}

// ScanFile scans a Python wheel or egg file by extracting its contents
// and scanning with appropriate sub-scanners.
func (s *WheelScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("failed to open wheel %s: %w", path, err)
	}

	var findings []types.Finding

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(f.Name))
		entryPath := fmt.Sprintf("%s!/%s", path, f.Name)

		entryContent, err := readZipEntry(f)
		if err != nil {
			continue
		}

		switch ext {
		case ".py", ".pyw":
			// Scan Python source files with the Python scanner
			pyFindings, err := s.pythonScanner.ScanFile(entryPath, entryContent)
			if err == nil {
				findings = append(findings, pyFindings...)
			}

		case ".so", ".pyd", ".dylib":
			// Scan C extensions with byte-pattern matcher
			soFindings := scanBytes(entryPath, entryContent)
			findings = append(findings, soFindings...)
		}
	}

	return scanner.AnnotateFindings(findings), nil
}
