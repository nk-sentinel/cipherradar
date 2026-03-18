package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff <before.json> <after.json>",
	Short: "Compare two CBOM files and show differences",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("diff not yet implemented")
		return nil
	},
}

func init() {
	diffCmd.Flags().StringP("output", "o", "", "output file path")
	diffCmd.Flags().StringP("format", "f", "text", "output format")

	rootCmd.AddCommand(diffCmd)
}
