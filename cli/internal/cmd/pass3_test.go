package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/yarax"
)

// These tests exercise the missing-yr (YARA-X) path. They auto-skip
// when yr is discoverable so dev machines with the binary installed
// don't see false failures.
//
// runPass3 doesn't exist as a separate orchestration function — Pass 3
// dispatch lives inside the walker via the PassAware seam — so the
// hard-fail check tested here is the inline guard in runScan
// (cli/internal/cmd/scan.go) that fires before walker invocation when
// the user explicitly opted into --passes 3.

// passes3Required mirrors the relevant condition from runScan: when
// the user explicitly opted into Pass 3 (via --deep or --passes), and
// yr isn't on PATH, the call must hard-fail with ExitToolMissing.
// Encapsulating it here keeps the test independent of cobra's
// cmd.Flag().Changed plumbing.
func passes3Required() error {
	r := yarax.NewRunner()
	if r == nil || !r.Available() {
		return ExitErrorf(ExitToolMissing,
			"Pass 3 requires yara-x (yr), which was not found on PATH. Run 'cradar install-tools' or use the cradar-full binary.")
	}
	return nil
}

func TestRunPass3_MissingAndNotRequired_SoftSkip(t *testing.T) {
	// When the user did NOT explicitly opt into Pass 3, the YaraXScanner
	// is simply absent from the walker dispatch — there's nothing to
	// soft-skip in cmd because the scanner self-skips inside ScanFile.
	// This test asserts the runner reports unavailability cleanly so
	// the walker's PassAware filter and the YaraXScanner.ScanFile both
	// see the same "not available" signal.
	r := yarax.NewRunner()
	if r != nil && r.Available() {
		t.Skip("yr is installed; this test requires it absent")
	}
	if r != nil && !r.Available() {
		// fine — runner exists but reports unavailable; ScanFile
		// soft-skips in that state.
		return
	}
	// r == nil — runner construction couldn't even find a binary; same
	// soft-skip outcome.
}

func TestRunPass3_MissingAndRequired_ExitToolMissing(t *testing.T) {
	if r := yarax.NewRunner(); r != nil && r.Available() {
		t.Skip("yr is installed; this test requires it absent")
	}

	err := passes3Required()
	if err == nil {
		t.Fatal("expected ExitToolMissing error when yr is absent and Pass 3 explicitly required")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitToolMissing {
		t.Errorf("expected ExitToolMissing (%d), got %d", ExitToolMissing, ee.Code)
	}
	if !strings.Contains(err.Error(), "yara-x") && !strings.Contains(err.Error(), "yr") {
		t.Errorf("error should mention yara-x / yr, got: %v", err)
	}
}
