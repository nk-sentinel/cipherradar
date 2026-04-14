package cmd

import (
	"errors"
	"strings"
	"testing"
)

// These tests assume opengrep is not installed in the test environment.
// If a future CI image bundles opengrep, both tests will be skipped
// rather than give false positives.

func TestRunPass2_MissingAndNotRequired_SoftSkip(t *testing.T) {
	findings, err := runPass2(t.TempDir(), "", false)
	if err != nil {
		if strings.Contains(err.Error(), "opengrep") {
			t.Skip("opengrep is installed; skipping missing-tool test")
		}
		t.Fatalf("expected nil error on soft skip, got: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings on soft skip, got %d", len(findings))
	}
}

func TestRunPass2_MissingAndRequired_ExitToolMissing(t *testing.T) {
	_, err := runPass2(t.TempDir(), "", true)
	if err == nil {
		t.Skip("opengrep is installed; skipping missing-tool test")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitToolMissing {
		t.Errorf("expected ExitToolMissing (%d), got %d", ExitToolMissing, ee.Code)
	}
	if !strings.Contains(err.Error(), "opengrep") {
		t.Errorf("error should mention opengrep: %v", err)
	}
}
