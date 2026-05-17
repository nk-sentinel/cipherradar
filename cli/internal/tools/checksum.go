package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerifySHA256 returns nil if the SHA-256 digest of the file at path matches
// expected (hex, case-insensitive). Returns an error describing the mismatch
// otherwise. Streams the file so memory is bounded for large binaries.
func VerifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("checksum: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("checksum: read %s: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))

	want := strings.TrimSpace(strings.ToLower(expected))
	if want == "" {
		return fmt.Errorf("checksum: expected digest is empty")
	}
	if got != want {
		return fmt.Errorf("checksum: mismatch for %s\n  want: %s\n  got:  %s", path, want, got)
	}
	return nil
}
