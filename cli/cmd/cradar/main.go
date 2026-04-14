package main

import (
	"fmt"
	"os"

	"github.com/nk-sentinel/cipherradar/cli/internal/cmd"
)

func main() {
	err := cmd.Execute()
	if err == nil {
		os.Exit(cmd.ExitOK)
	}

	// cobra has already printed its own "Error: ..." line for most errors,
	// but typed ExitErrors carry a code we must honour.
	code := cmd.ExitCode(err)
	if code == cmd.ExitFindings && !errorAlreadyPrinted(err) {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
	os.Exit(code)
}

// errorAlreadyPrinted returns true when cobra's RunE path has taken
// responsibility for printing the error (the normal path). Keeping this
// guard prevents a duplicate "Error:" line for typed ExitErrors when
// cobra's SilenceErrors is not set.
func errorAlreadyPrinted(err error) bool {
	// Cobra prints every RunE-returned error by default. This is a no-op
	// hook reserved for future customisation (e.g. if a subcommand sets
	// SilenceErrors, we would detect it here). Leaving the boolean true
	// matches current behaviour — cobra handles printing.
	_ = err
	return true
}
