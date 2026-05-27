package output

import (
	"strings"
	"testing"
)

func TestWriterFactory_ReturnsCorrectWriter(t *testing.T) {
	tests := []struct {
		format     string
		wantFormat string
	}{
		{"cyclonedx-json", "cyclonedx-json"},
		{"sarif", "sarif"},
		{"text", "text"},
		// "pdf" is registered by output/pdf.init() and is covered by the
		// external test in pdf_test.go (package output_test) which imports
		// output/pdf to trigger registration.
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
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.writer.Format(); got != tt.want {
				t.Errorf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}
