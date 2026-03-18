package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestWriterFactory_ReturnsCorrectWriter(t *testing.T) {
	tests := []struct {
		format     string
		wantFormat string
		wantType   string
	}{
		{"cyclonedx-json", "cyclonedx-json", "*output.CycloneDXJSONWriter"},
		{"sarif", "sarif", "*output.SARIFWriter"},
		{"text", "text", "*output.TextWriter"},
		{"pdf", "pdf", "*output.PDFWriter"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			w, err := WriterFactory(tt.format)
			if err != nil {
				t.Fatalf("WriterFactory(%q) returned error: %v", tt.format, err)
			}
			if w == nil {
				t.Fatalf("WriterFactory(%q) returned nil writer", tt.format)
			}
			if got := w.Format(); got != tt.wantFormat {
				t.Errorf("Format() = %q, want %q", got, tt.wantFormat)
			}
		})
	}
}

func TestWriterFactory_UnknownFormat(t *testing.T) {
	_, err := WriterFactory("unknown-format")
	if err == nil {
		t.Fatal("WriterFactory(\"unknown-format\") should return an error")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Errorf("error message should mention unsupported format, got: %v", err)
	}
}

func TestWriterFormat(t *testing.T) {
	tests := []struct {
		writer Writer
		want   string
	}{
		{&CycloneDXJSONWriter{}, "cyclonedx-json"},
		{&SARIFWriter{}, "sarif"},
		{&TextWriter{}, "text"},
		{&PDFWriter{}, "pdf"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.writer.Format(); got != tt.want {
				t.Errorf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteScanResult_StubsReturnNotImplemented(t *testing.T) {
	result := &types.ScanResult{
		Target:       "/tmp/test-project",
		Findings:     []types.Finding{},
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		PassesRun:    []int{1},
		FilesScanned: 0,
		Errors:       []types.ScanError{},
	}

	tests := []struct {
		name   string
		writer Writer
	}{
		{"cyclonedx-json", &CycloneDXJSONWriter{}},
		{"sarif", &SARIFWriter{}},
		{"text", &TextWriter{}},
		{"pdf", &PDFWriter{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tt.writer.WriteScanResult(&buf, result)
			if err == nil {
				t.Fatalf("%s WriteScanResult should return error for stub", tt.name)
			}
			if !strings.Contains(err.Error(), "not yet implemented") {
				t.Errorf("error should contain 'not yet implemented', got: %v", err)
			}
		})
	}
}
