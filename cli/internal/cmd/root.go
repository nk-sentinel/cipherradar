package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cbom",
	Short: "CipherRadar — Cryptography Bill of Materials scanner",
	Long:  "CipherRadar — Cryptography Bill of Materials scanner",
}

func init() {
	rootCmd.PersistentFlags().String("config", ".cbom.yml", "path to configuration file")
	rootCmd.PersistentFlags().Bool("verbose", false, "enable verbose output")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
