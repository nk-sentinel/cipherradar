package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan a project for cryptographic assets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("scan not yet implemented")
		return nil
	},
}

func init() {
	scanCmd.Flags().StringP("output", "o", "", "output file path")
	scanCmd.Flags().StringP("format", "f", "cyclonedx-json", "output format (cyclonedx-json, sarif, text, pdf)")
	scanCmd.Flags().String("severity", "low", "minimum severity level to report")
	scanCmd.Flags().String("passes", "1,2,3", "comma-separated list of scan passes to run")
	scanCmd.Flags().String("branch", "", "git branch to scan (for git URLs)")
	scanCmd.Flags().Bool("validate", false, "validate output against CycloneDX 1.7 schema")

	rootCmd.AddCommand(scanCmd)
}
