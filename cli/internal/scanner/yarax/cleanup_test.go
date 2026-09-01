package yarax

import (
	"os"
	"testing"
)

// TestCleanupEmbeddedRules ensures the embedded-ruleset tempdir is removed and
// the memo reset, so Pass 3 stops leaking /tmp/cradar-yara-rules-* (gh #82).
func TestCleanupEmbeddedRules(t *testing.T) {
	// Start clean so this test is order-independent.
	CleanupEmbeddedRules()

	dir := ensureEmbeddedRulesDir()
	if dir == "" {
		t.Skip("embedded ruleset failed to extract (tempfs?) — nothing to clean")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("extracted rules dir should exist: %v", err)
	}

	CleanupEmbeddedRules()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("rules dir %q should be removed after cleanup, stat err=%v", dir, err)
	}
	// Memo reset → a subsequent call re-extracts to a fresh dir.
	dir2 := ensureEmbeddedRulesDir()
	if dir2 == "" || dir2 == dir {
		t.Errorf("expected re-extraction to a fresh dir after cleanup; got %q (was %q)", dir2, dir)
	}
	CleanupEmbeddedRules() // don't leak from the test either
}
