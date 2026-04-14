package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/config"
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
	reportCmd.Flags().StringP("output", "o", "", "output file path (format inferred from extension when set)")
	reportCmd.Flags().StringP("format", "f", "", "output format override (cyclonedx-json, sarif, text, pdf, sonarqube-generic); default pdf when unset and no extension")

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

	// Resolve format: --format override > file-extension dispatch >
	// .cradar.yml default_format > "pdf" fallback. Report's default is pdf
	// (rather than scan's cyclonedx-json) because reports are typically the
	// human-readable artifact handed off.
	explicitFormat, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")

	cfgFormat := ""
	if cfgPath, _ := cmd.Flags().GetString("config"); cfgPath != "" {
		if cfg, err := config.LoadConfig(cfgPath); err == nil && cfg != nil {
			cfgFormat = cfg.Format
		}
	}

	format := output.ResolveOutputFormat(outputPath, explicitFormat, cfgFormat, "pdf")
	if err := output.ValidateFormat(format); err != nil {
		return ExitErrorf(ExitConfig, "%v", err)
	}
	writer, err := output.WriterFactory(format)
	if err != nil {
		return err
	}

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
// Used only when no --output path is supplied and the report needs a
// sensible default filename.
func formatExtension(format string) string {
	switch format {
	case "cyclonedx-json":
		return "json"
	case "sarif":
		return "sarif"
	case "text":
		return "txt"
	case "sonarqube-generic":
		return "sonar.json"
	default:
		return format
	}
}
