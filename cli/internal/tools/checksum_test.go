package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySHA256_MatchAccepted(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	if err := VerifySHA256(path, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifySHA256_MismatchRejected(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := VerifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should say 'mismatch': %v", err)
	}
}

func TestVerifySHA256_CaseInsensitiveHex(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := VerifySHA256(path, "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"); err != nil {
		t.Errorf("expected nil (case-insensitive), got %v", err)
	}
}

func TestVerifySHA256_MissingFile(t *testing.T) {
	err := VerifySHA256(filepath.Join(t.TempDir(), "nope"), "00")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
