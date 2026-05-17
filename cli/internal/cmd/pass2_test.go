package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
)

// These tests exercise the missing-opengrep path. They auto-skip when
// opengrep is discoverable so dev machines with the binary installed
// don't see false failures.

func TestRunPass2_MissingAndNotRequired_SoftSkip(t *testing.T) {
	if opengrep.NewRunner() != nil {
		t.Skip("opengrep is installed; this test requires it absent")
	}
	findings, err := runPass2(t.TempDir(), "", false)
	if err != nil {
		t.Fatalf("expected nil error on soft skip, got: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings on soft skip, got %d", len(findings))
	}
}

func TestRunPass2_MissingAndRequired_ExitToolMissing(t *testing.T) {
	if opengrep.NewRunner() != nil {
		t.Skip("opengrep is installed; this test requires it absent")
	}
	_, err := runPass2(t.TempDir(), "", true)
	if err == nil {
		t.Fatal("expected ExitToolMissing error, got nil")
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
