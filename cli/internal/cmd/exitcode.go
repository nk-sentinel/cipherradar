package cmd

import (
	"errors"
	"fmt"
)

// Exit codes form a stable contract used by CI pipelines and documentation.
// See ADR-036 for the full policy.
const (
	ExitOK           = 0 // clean scan, no findings at or above --fail-on
	ExitFindings     = 1 // findings above --fail-on threshold (also: generic runtime error)
	ExitWarnings     = 2 // warnings only (policy warn path)
	ExitConfig       = 3 // config parse error, schema validation error, bad flag combo
	ExitToolMissing  = 4 // required external tool (OpenGrep, YARA-X) is not installed
)

// ExitError carries an exit code alongside an error. Subcommands return
// ExitErrors instead of calling os.Exit so that deferred cleanup runs and
// a single top-level handler can map the code. See main.go.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return fmt.Sprintf("exit code %d", exitCodeOrDefault(e))
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func exitCodeOrDefault(e *ExitError) int {
	if e == nil {
		return ExitOK
	}
	return e.Code
}

// NewExitError wraps msg in an ExitError with the given code.
func NewExitError(code int, msg string) error {
	return &ExitError{Code: code, Err: errors.New(msg)}
}

// ExitErrorf wraps an fmt.Errorf-style error with a code.
func ExitErrorf(code int, format string, a ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, a...)}
}

// WithExitCode wraps an existing error with an exit code. Passing a nil
// error returns nil so callers can write `return WithExitCode(3, err)`
// without a branch.
func WithExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		// Don't double-wrap; keep the most specific code.
		return err
	}
	return &ExitError{Code: code, Err: err}
}

// ExitCode extracts the exit code from an error. Returns ExitOK for nil
// and ExitFindings (1) for any non-ExitError.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitFindings
}
