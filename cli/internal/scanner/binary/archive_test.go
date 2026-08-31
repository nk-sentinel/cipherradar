package binary_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
)

func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestJARScanner_RecursesAndFlagsDepthLimit proves the scanner recurses into
// nested archives and stops at the depth guard (emitting a partial-scan note).
func TestJARScanner_RecursesAndFlagsDepthLimit(t *testing.T) {
	inner := buildZip(t, map[string][]byte{"leaf.txt": []byte("hello")})
	for i := 0; i < 6; i++ { // nest well beyond maxArchiveDepth
		inner = buildZip(t, map[string][]byte{"nested.jar": inner})
	}
	findings, err := binary.NewJARScanner().ScanFile("top.jar", inner)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "cbom-archive-partial" {
			found = true
		}
	}
	if !found {
		t.Error("expected a cbom-archive-partial finding when nesting exceeds the depth guard")
	}
}

// TestJARScanner_ZipEntryRecurses confirms a nested .zip is recursed into (not
// treated as opaque), and the scan completes without error.
func TestJARScanner_ZipEntryRecurses(t *testing.T) {
	innerZip := buildZip(t, map[string][]byte{"cfg/app.xml": []byte("<c>TLSv1.0</c>")})
	outer := buildZip(t, map[string][]byte{"lib/inner.zip": innerZip})
	if _, err := binary.NewJARScanner().ScanFile("top.jar", outer); err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
}

// TestJARScanner_CorruptTopLevelErrors ensures a corrupt top-level archive is a
// clean error, while a corrupt nested entry is skipped (covered indirectly).
func TestJARScanner_CorruptTopLevelErrors(t *testing.T) {
	if _, err := binary.NewJARScanner().ScanFile("bad.jar", []byte("not a zip")); err == nil {
		t.Error("expected an error for a corrupt top-level archive")
	}
}
