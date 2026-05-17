package cmd

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCode_NilIsOK(t *testing.T) {
	if got := ExitCode(nil); got != ExitOK {
		t.Errorf("ExitCode(nil) = %d; want %d", got, ExitOK)
	}
}

func TestExitCode_PlainErrorDefaultsToOne(t *testing.T) {
	if got := ExitCode(errors.New("boom")); got != ExitFindings {
		t.Errorf("ExitCode(plain) = %d; want %d", got, ExitFindings)
	}
}

func TestExitCode_HonoursTypedCode(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{"warnings", ExitWarnings},
		{"config", ExitConfig},
		{"toolMissing", ExitToolMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewExitError(tt.code, "x")
			if got := ExitCode(err); got != tt.code {
				t.Errorf("ExitCode = %d; want %d", got, tt.code)
			}
		})
	}
}

func TestExitCode_WrappedTypedStillMaps(t *testing.T) {
	inner := NewExitError(ExitConfig, "bad config")
	wrapped := fmt.Errorf("loading: %w", inner)
	if got := ExitCode(wrapped); got != ExitConfig {
		t.Errorf("wrapped ExitError lost code: got %d, want %d", got, ExitConfig)
	}
}

func TestWithExitCode_NilPassthrough(t *testing.T) {
	if err := WithExitCode(ExitConfig, nil); err != nil {
		t.Errorf("nil in, expected nil out, got %v", err)
	}
}

func TestWithExitCode_NoDoubleWrap(t *testing.T) {
	inner := NewExitError(ExitConfig, "inner")
	wrapped := WithExitCode(ExitFindings, inner)
	if got := ExitCode(wrapped); got != ExitConfig {
		t.Errorf("double-wrap should keep inner code; got %d, want %d", got, ExitConfig)
	}
}

func TestExitErrorf_PreservesFormatting(t *testing.T) {
	err := ExitErrorf(ExitConfig, "bad value: %q", "xyz")
	want := `bad value: "xyz"`
	if err.Error() != want {
		t.Errorf("message: got %q, want %q", err.Error(), want)
	}
	if ExitCode(err) != ExitConfig {
		t.Errorf("code: got %d, want %d", ExitCode(err), ExitConfig)
	}
}
