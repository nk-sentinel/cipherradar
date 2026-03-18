package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report <cbom.json>",
	Short: "Generate a human-readable report from a CBOM",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("report not yet implemented")
		return nil
	},
}

func init() {
	reportCmd.Flags().StringP("output", "o", "", "output file path")
	reportCmd.Flags().StringP("format", "f", "pdf", "output format")

	rootCmd.AddCommand(reportCmd)
}
