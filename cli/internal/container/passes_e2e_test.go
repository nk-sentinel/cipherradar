package container

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/yarax"
	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
)

// TestScanImage_Pass2RunsOnImageContent proves OpenGrep (Pass 2) actually runs
// over materialized layer content — the core gh #83 fix. Skips when opengrep
// isn't installed.
func TestScanImage_Pass2RunsOnImageContent(t *testing.T) {
	if opengrep.NewRunner() == nil {
		t.Skip("opengrep not installed")
	}
	tarPath := createTestImageTar(t, map[string][]byte{
		"app/crypto.py": []byte("from cryptography.hazmat.primitives.ciphers import Cipher\nimport hashlib\nh = hashlib.md5(b\"x\")\n"),
	})
	result, err := ScanImage(tarPath, scannerinit.DefaultRegistry(), []int{1, 2})
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if !containsPassInt(result.PassesRun, 2) {
		t.Errorf("PassesRun should include 2 when opengrep ran on image content, got %v", result.PassesRun)
	}
}

// TestScanImage_Pass3RunsOnImageBinaries proves YARA-X (Pass 3) reaches a
// binary materialized from a layer — previously binaries were pre-filtered.
// Skips when yr isn't installed.
func TestScanImage_Pass3RunsOnImageBinaries(t *testing.T) {
	if r := yarax.NewRunner(); r == nil || !r.Available() {
		t.Skip("yr not installed")
	}
	// A file the walker routes to Pass 3 (extensionless / binary), with an
	// OpenSSL version banner the embedded ruleset recognizes.
	tarPath := createTestImageTar(t, map[string][]byte{
		"usr/lib/libssl.so": append([]byte("\x7fELF\x00\x00 "), []byte("OpenSSL 3.0.1 14 Dec 2021 ")...),
	})
	result, err := ScanImage(tarPath, scannerinit.DefaultRegistry(), []int{1, 3})
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if !containsPassInt(result.PassesRun, 3) {
		t.Errorf("PassesRun should include 3 when yr ran on image binaries, got %v", result.PassesRun)
	}
}
