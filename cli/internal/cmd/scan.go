package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/rules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan a project for cryptographic assets",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringP("output", "o", "", "output file path")
	scanCmd.Flags().StringP("format", "f", "cyclonedx-json", "output format (cyclonedx-json, sarif, text, pdf)")
	scanCmd.Flags().String("severity", "low", "minimum severity level to report")
	scanCmd.Flags().String("passes", "1,2,3", "comma-separated list of scan passes to run")
	scanCmd.Flags().String("branch", "", "git branch to scan (for git URLs)")
	scanCmd.Flags().Bool("validate", false, "validate output against CycloneDX 1.7 schema")
	scanCmd.Flags().String("rules-dir", "", "directory containing OpenGrep YAML rules for Pass 2")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	// Parse passes flag.
	passesStr, _ := cmd.Flags().GetString("passes")
	passes, err := parsePasses(passesStr)
	if err != nil {
		return fmt.Errorf("invalid --passes flag: %w", err)
	}

	// Create scanner registry with all built-in scanners.
	registry := scannerinit.DefaultRegistry()

	// Run Pass 1 scan.
	result, err := scanner.ScanDir(targetPath, registry, passes)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Run Pass 2 (OpenGrep taint analysis) if requested.
	if containsPass(passes, 2) {
		rulesDir, _ := cmd.Flags().GetString("rules-dir")
		if rulesDir == "" {
			rulesDir = os.Getenv("CBOM_RULES_DIR")
		}

		pass2Findings, pass2Err := runPass2(targetPath, rulesDir)
		if pass2Err != nil {
			result.Errors = append(result.Errors, types.ScanError{
				File:    "",
				Message: fmt.Sprintf("Pass 2 error: %v", pass2Err),
			})
		} else if pass2Findings != nil {
			result.Findings = opengrep.DeduplicateFindings(result.Findings, pass2Findings)
		}
	}

	// Get the output format.
	format, _ := cmd.Flags().GetString("format")
	writer, err := output.WriterFactory(format)
	if err != nil {
		return err
	}

	// Determine output destination.
	outputPath, _ := cmd.Flags().GetString("output")
	dest := cmd.OutOrStdout()
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		dest = f
	}

	// Write the output.
	if err := writer.WriteScanResult(dest, result); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	return nil
}

// parsePasses parses a comma-separated list of pass numbers (e.g. "1,2,3").
func parsePasses(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	passes := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid pass number %q: %w", p, err)
		}
		if n < 1 || n > 3 {
			return nil, fmt.Errorf("pass number must be 1-3, got %d", n)
		}
		passes = append(passes, n)
	}
	if len(passes) == 0 {
		return nil, fmt.Errorf("no passes specified")
	}
	return passes, nil
}

// containsPass returns true if the passes slice contains the given pass number.
func containsPass(passes []int, pass int) bool {
	for _, p := range passes {
		if p == pass {
			return true
		}
	}
	return false
}

// runPass2 runs OpenGrep Pass 2 analysis if the binary is available.
// Returns nil findings (not an error) if OpenGrep is not installed.
// If no rules directory is specified, uses embedded rules extracted to a temp dir.
func runPass2(target string, rulesDir string) ([]types.Finding, error) {
	runner := opengrep.NewRunner()
	if runner == nil || !runner.Available() {
		fmt.Fprintln(os.Stderr, "Pass 2 skipped — opengrep not found. Run 'cbom install-tools' or use cbom-full.")
		return nil, nil
	}

	// Use embedded rules if no explicit rules directory provided.
	if rulesDir == "" {
		tmpDir, err := rules.ExtractToTempDir()
		if err != nil {
			return nil, fmt.Errorf("extracting embedded rules: %w", err)
		}
		defer os.RemoveAll(tmpDir)
		rulesDir = tmpDir
	}

	return runner.Scan(target, rulesDir)
}
