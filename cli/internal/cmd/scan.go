package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/container"
	"github.com/nk-sentinel/cipherradar/cli/internal/joern"
	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/push"
	"github.com/nk-sentinel/cipherradar/cli/internal/rules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/nk-sentinel/cipherradar/cli/internal/validation"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project or container image for cryptographic assets",
	Long: `Scan a project directory or container image for cryptographic assets.

When --container is set, the argument is an image reference (e.g. nginx:latest,
gcr.io/project/image:tag) or a local tar file path. This flag is mutually
exclusive with the directory path argument.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("output", "o", "", "output file path")
	scanCmd.Flags().StringP("format", "f", "cyclonedx-json", "output format (cyclonedx-json, sarif, text, pdf)")
	scanCmd.Flags().String("severity", "low", "minimum severity level to report")
	scanCmd.Flags().String("passes", "1,2,3", "comma-separated list of scan passes to run")
	scanCmd.Flags().String("branch", "", "git branch to scan (for git URLs)")
	scanCmd.Flags().Bool("validate", false, "validate output against CycloneDX 1.7 schema")
	scanCmd.Flags().String("rules-dir", "", "directory containing OpenGrep YAML rules for Pass 2")
	scanCmd.Flags().String("queries-dir", "", "directory containing Joern .sc query scripts for Pass 3")
	scanCmd.Flags().Bool("deep", false, "alias for --passes 1,2,3 (enables inter-procedural analysis)")

	// Pre-commit hook support flags.
	scanCmd.Flags().Bool("fast", false, "run Pass 1 only (no OpenGrep/Joern), skip files >100KB")
	scanCmd.Flags().Bool("staged-only", false, "only scan files in git staging area (git diff --cached)")
	scanCmd.Flags().String("fail-on", "", "exit non-zero if findings at or above this severity (critical, high, medium, low, info)")

	// Container image scanning.
	scanCmd.Flags().String("container", "", "scan a container image (reference or local .tar path)")

	// Push flags (ADR-025).
	scanCmd.Flags().Bool("push", false, "upload scan results to CipherRadar portal after scan")
	scanCmd.Flags().String("project", "", "project name for portal upload (required with --push)")
	scanCmd.Flags().String("group", "", "group path for portal upload (optional)")
	scanCmd.Flags().String("api-url", "", "CipherRadar portal API URL")
	scanCmd.Flags().String("api-key", "", "API key for portal authentication (also reads CRADAR_API_KEY env)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	containerRef, _ := cmd.Flags().GetString("container")

	// Validate mutually exclusive arguments: --container vs path.
	if containerRef != "" && len(args) > 0 {
		return fmt.Errorf("--container and path argument are mutually exclusive")
	}
	if containerRef == "" && len(args) == 0 {
		return fmt.Errorf("either a path argument or --container flag is required")
	}

	// Parse passes flag. --deep is an alias for --passes 1,2,3.
	// --fast overrides to pass 1 only.
	fast, _ := cmd.Flags().GetBool("fast")
	deep, _ := cmd.Flags().GetBool("deep")
	passesStr, _ := cmd.Flags().GetString("passes")
	if fast {
		passesStr = "1"
	} else if deep {
		passesStr = "1,2,3"
	}
	passes, err := parsePasses(passesStr)
	if err != nil {
		return fmt.Errorf("invalid --passes flag: %w", err)
	}

	// Determine scan options.
	stagedOnly, _ := cmd.Flags().GetBool("staged-only")

	// Build scan options.
	scanOpts := scanner.ScanOptions{
		Fast:       fast,
		StagedOnly: stagedOnly,
	}

	// Create scanner registry with all built-in scanners.
	registry := scannerinit.DefaultRegistry()

	var result *types.ScanResult

	if containerRef != "" {
		// Container image scanning mode.
		result, err = container.ScanImage(containerRef, registry, passes)
		if err != nil {
			return fmt.Errorf("container scan failed: %w", err)
		}
	} else {
		// Directory scanning mode.
		targetPath := args[0]

		// If --staged-only, resolve staged file list from git.
		if scanOpts.StagedOnly {
			stagedFiles, gitErr := getStagedFiles(targetPath)
			if gitErr != nil {
				return fmt.Errorf("--staged-only: %w", gitErr)
			}
			scanOpts.FileList = stagedFiles
		}

		// Run Pass 1 scan.
		result, err = scanner.ScanDirWithOptions(targetPath, registry, passes, scanOpts)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		// Run Pass 2 (OpenGrep taint analysis) if requested.
		if containsPass(passes, 2) {
			rulesDir, _ := cmd.Flags().GetString("rules-dir")
			if rulesDir == "" {
				rulesDir = os.Getenv("CRADAR_RULES_DIR")
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

		// Run Pass 3 (Joern inter-procedural analysis) if requested.
		if containsPass(passes, 3) {
			queriesDir, _ := cmd.Flags().GetString("queries-dir")
			if queriesDir == "" {
				queriesDir = os.Getenv("CRADAR_QUERIES_DIR")
			}

			pass3Findings, pass3Err := runPass3(targetPath, queriesDir)
			if pass3Err != nil {
				result.Errors = append(result.Errors, types.ScanError{
					File:    "",
					Message: fmt.Sprintf("Pass 3 error: %v", pass3Err),
				})
			} else if pass3Findings != nil {
				result.Findings = joern.DeduplicateFindings(result.Findings, pass3Findings)
			}
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

	// Validate output against CycloneDX 1.7 schema if requested.
	validate, _ := cmd.Flags().GetBool("validate")
	if validate && format == "cyclonedx-json" {
		bom := output.ConvertScanResult(result)
		jsonBytes, err := json.MarshalIndent(bom, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal for validation: %w", err)
		}

		valResult, err := validation.ValidateCycloneDXJSON(jsonBytes)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}
		if !valResult.Valid {
			fmt.Fprintf(os.Stderr, "CycloneDX 1.7 schema validation FAILED:\n")
			for _, e := range valResult.Errors {
				fmt.Fprintf(os.Stderr, "  %s: %s\n", e.Path, e.Message)
			}
			return fmt.Errorf("schema validation failed with %d errors", len(valResult.Errors))
		}
		fmt.Fprintln(os.Stderr, "CycloneDX 1.7 schema validation PASSED")
	}

	// Push scan results to portal if --push is set (ADR-025).
	pushEnabled, _ := cmd.Flags().GetBool("push")
	if pushEnabled {
		if err := runPush(cmd, result); err != nil {
			return fmt.Errorf("push failed: %w", err)
		}
	}

	// Check --fail-on severity gate.
	failOn, _ := cmd.Flags().GetString("fail-on")
	if failOn != "" {
		if err := checkFailOn(result.Findings, failOn); err != nil {
			return err
		}
	}

	return nil
}

// runPush uploads scan results to the CipherRadar portal.
// Flag values take precedence over config file values.
func runPush(cmd *cobra.Command, result *types.ScanResult) error {
	// Load config file for defaults.
	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not load config file %s: %v\n", configPath, err)
		cfg = &config.Config{}
	}

	// Resolve flags with config file fallbacks.
	apiURL, _ := cmd.Flags().GetString("api-url")
	if apiURL == "" {
		apiURL = cfg.APIURL
	}
	if apiURL == "" {
		return fmt.Errorf("--api-url is required (or set api_url in .cradar.yml)")
	}

	apiKey, _ := cmd.Flags().GetString("api-key")
	if apiKey == "" {
		apiKey = os.Getenv("CRADAR_API_KEY")
	}
	apiKey = cfg.ResolveAPIKey(apiKey)
	if apiKey == "" {
		return fmt.Errorf("--api-key or CRADAR_API_KEY env var is required")
	}

	project, _ := cmd.Flags().GetString("project")
	if project == "" {
		project = cfg.Project
	}
	if project == "" {
		return fmt.Errorf("--project is required with --push (or set project in .cradar.yml)")
	}

	group, _ := cmd.Flags().GetString("group")
	if group == "" {
		group = cfg.Group
	}

	branch, _ := cmd.Flags().GetString("branch")
	// commitSHA is not yet a flag; leave empty for now.
	commitSHA := ""

	client := push.NewPushClient(apiURL, apiKey)
	resp, err := client.UploadScanResult(result, project, group, branch, commitSHA)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Scan uploaded to portal (scan: %s, project: %s)\n", resp.ScanID, resp.ProjectID)
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
		fmt.Fprintln(os.Stderr, "Pass 2 skipped — opengrep not found. Run 'cradar install-tools' or use cradar-full.")
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

// runPass3 runs Joern Pass 3 inter-procedural analysis if the binary is available.
// Returns nil findings (not an error) if Joern is not installed.
// If no queries directory is specified, uses embedded query scripts extracted to a temp dir.
func runPass3(target string, queriesDir string) ([]types.Finding, error) {
	runner := joern.NewRunner()
	if runner == nil || !runner.Available() {
		fmt.Fprintln(os.Stderr, "Pass 3 skipped — joern not found. Run 'cradar install-tools' or use cradar-full.")
		return nil, nil
	}

	return runner.Scan(target, queriesDir)
}

// getStagedFiles returns the list of staged file paths (relative to the repo
// root) by running `git diff --cached --name-only`.
func getStagedFiles(repoDir string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoDir, "diff", "--cached", "--name-only")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running git diff --cached: %w", err)
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// scanSeverityRank maps severity strings to numeric ranks for fail-on comparison.
var scanSeverityRank = map[types.Severity]int{
	types.SeverityInfo:     0,
	types.SeverityLow:      1,
	types.SeverityMedium:   2,
	types.SeverityHigh:     3,
	types.SeverityCritical: 4,
}

// checkFailOn returns an error if any finding meets or exceeds the given
// severity threshold.
func checkFailOn(findings []types.Finding, failOn string) error {
	threshold, ok := scanSeverityRank[types.Severity(strings.ToLower(failOn))]
	if !ok {
		return fmt.Errorf("invalid --fail-on severity: %q (valid: critical, high, medium, low, info)", failOn)
	}

	for _, f := range findings {
		rank, ok := scanSeverityRank[f.Severity]
		if !ok {
			continue
		}
		if rank >= threshold {
			return fmt.Errorf("scan failed: finding %q has severity %s (fail-on threshold: %s)",
				f.Name, f.Severity, failOn)
		}
	}
	return nil
}
