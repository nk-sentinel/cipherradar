package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nk-sentinel/cipherradar/cli/internal/diff"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff <before.json> <after.json>",
	Short: "Compare two CBOM files and show differences",
	Args:  cobra.ExactArgs(2),
	RunE:  runDiff,
}

func init() {
	diffCmd.Flags().StringP("output", "o", "", "output file path")
	diffCmd.Flags().StringP("format", "f", "text", "output format (text or json)")

	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) error {
	beforePath := args[0]
	afterPath := args[1]

	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	// Load both CBOM files.
	beforeBOM, err := diff.LoadBOM(beforePath)
	if err != nil {
		return fmt.Errorf("loading before CBOM: %w", err)
	}
	afterBOM, err := diff.LoadBOM(afterPath)
	if err != nil {
		return fmt.Errorf("loading after CBOM: %w", err)
	}

	// Compare.
	result := diff.CompareBOMs(beforeBOM, afterBOM)
	result.Before = filepath.Base(beforePath)
	result.After = filepath.Base(afterPath)

	// Determine output writer.
	w := cmd.OutOrStdout()
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	// Format output.
	switch format {
	case "json":
		return diff.FormatJSON(w, result)
	case "text", "":
		return diff.FormatText(w, result)
	default:
		return fmt.Errorf("unsupported format: %s (use 'text' or 'json')", format)
	}
}
