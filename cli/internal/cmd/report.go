package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/policy"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report <cbom.json>",
	Short: "Generate a human-readable report from a CBOM",
	Args:  cobra.ExactArgs(1),
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringP("output", "o", "", "output file path")
	reportCmd.Flags().StringP("format", "f", "pdf", "output format (cyclonedx-json, sarif, text, pdf)")

	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	cbomPath := args[0]

	// Load findings from the CBOM file.
	findings, err := policy.LoadCBOM(cbomPath)
	if err != nil {
		return fmt.Errorf("loading CBOM: %w", err)
	}

	// Build a ScanResult from the loaded findings.
	now := time.Now()
	result := &types.ScanResult{
		Target:   cbomPath,
		Findings: findings,
		StartTime: now,
		EndTime:   now,
	}

	// Get the output writer for the requested format.
	format, _ := cmd.Flags().GetString("format")
	writer, err := output.WriterFactory(format)
	if err != nil {
		return err
	}

	// Determine output destination.
	outputPath, _ := cmd.Flags().GetString("output")
	if outputPath == "" {
		outputPath = "report." + formatExtension(format)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot create output file: %w", err)
	}
	defer f.Close()

	if err := writer.WriteScanResult(f, result); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Report written to %s (%d findings)\n", outputPath, len(findings))
	return nil
}

// formatExtension returns the file extension for a given output format.
func formatExtension(format string) string {
	switch format {
	case "cyclonedx-json":
		return "json"
	case "sarif":
		return "sarif"
	case "text":
		return "txt"
	default:
		return format
	}
}
