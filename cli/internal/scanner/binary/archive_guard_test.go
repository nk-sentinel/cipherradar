package binary

import (
	"archive/zip"
	"bytes"
	"testing"
)

// TestReadZipEntryLimited_BombGuard verifies the reader never trusts the
// declared entry size: it bounds the read at the budget and rejects an entry
// that would exceed it, so a decompression bomb cannot exhaust memory.
func TestReadZipEntryLimited_BombGuard(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]

	// Budget smaller than the entry → rejected as too large.
	if _, _, err := readZipEntryLimited(f, 100); err != errEntryTooLarge {
		t.Errorf("small budget: expected errEntryTooLarge, got %v", err)
	}
	// Budget larger than the entry → reads exactly the 1000 bytes.
	data, n, err := readZipEntryLimited(f, 5000)
	if err != nil || n != 1000 || len(data) != 1000 {
		t.Errorf("ample budget: got n=%d len=%d err=%v, want 1000/1000/nil", n, len(data), err)
	}
}

func TestPartialArchiveFinding(t *testing.T) {
	f := partialArchiveFinding("app.jar")
	if f.RuleID != "cbom-archive-partial" {
		t.Errorf("ruleID = %q, want cbom-archive-partial", f.RuleID)
	}
	if f.Severity != "low" {
		t.Errorf("severity = %q, want low", f.Severity)
	}
}
