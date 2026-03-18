package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version is set via ldflags at build time.
	Version = "dev"
	// Commit is set via ldflags at build time.
	Commit = "none"
	// BuildDate is set via ldflags at build time.
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version, commit, and build date",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("cbom %s\ncommit: %s\nbuilt:  %s\n", Version, Commit, BuildDate)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
