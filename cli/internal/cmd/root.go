package cmd

import (
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cradar",
	Short: "CipherRadar — cryptographic asset scanner, CBOM generator, and compliance checker",
	Long:  "CipherRadar — cryptographic asset scanner, CBOM generator, and compliance checker",
}

func init() {
	rootCmd.PersistentFlags().String("config", ".cradar.yml", "path to configuration file")
	rootCmd.PersistentFlags().Bool("verbose", false, "enable verbose output")
}

// Execute runs the root command.
func Execute() error {
	output.AppVersion = Version
	return rootCmd.Execute()
}
