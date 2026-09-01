package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/baseline"
	"github.com/nk-sentinel/cipherradar/cli/internal/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/container"
	"github.com/nk-sentinel/cipherradar/cli/internal/deps"
	"github.com/nk-sentinel/cipherradar/cli/internal/diff"
	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	pdfpkg "github.com/nk-sentinel/cipherradar/cli/internal/output/pdf"
	"github.com/nk-sentinel/cipherradar/cli/internal/push"
	"github.com/nk-sentinel/cipherradar/cli/internal/rulefilter"
	"github.com/nk-sentinel/cipherradar/cli/internal/rules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/astrules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/fingerprint"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/keysize"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/keystore"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/yarax"
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
	scanCmd.Flags().StringSliceP("output", "o", nil, "output file path (repeatable; format inferred from file extension, e.g. .json/.sarif/.pdf/.sonar.json/.cbom.json)")
	scanCmd.Flags().StringP("format", "f", "", "output format when writing to stdout or overriding extension dispatch (cyclonedx-json, sarif, text, table, pdf, sonarqube-generic)")
	scanCmd.Flags().String("severity", "low", "minimum severity level to report")
	scanCmd.Flags().String("passes", "1,2", "comma-separated list of scan passes to run (1=AST, 2=OpenGrep, 3=YARA-X binary)")
	scanCmd.Flags().String("branch", "", "git branch to scan (for git URLs)")
	scanCmd.Flags().Bool("validate", false, "validate output against CycloneDX 1.7 schema")
	scanCmd.Flags().Bool("strict-validate", false,
		"fail the scan if any output value falls outside the CycloneDX 1.7 enum closed sets (default: warn only)")
	scanCmd.Flags().String("rules-dir", "", "directory containing OpenGrep YAML rules for Pass 2")
	scanCmd.Flags().String("yara-rules-dir", "", "directory containing YARA-X (.yar) rules for Pass 3; replaces the embedded ruleset (also reads CRADAR_YARA_RULES_DIR)")
	scanCmd.Flags().String("ast-rules-dir", "", "directory containing external Pass-1 AST detection tables (<lang>.yml); replaces the embedded tables per-language (also reads CRADAR_AST_RULES_DIR)")
	scanCmd.Flags().Bool("deep", false, "alias for --passes 1,2,3 (taint analysis + YARA-X binary scan)")

	// Pre-commit hook support flags.
	scanCmd.Flags().Bool("fast", false, "run Pass 1 only (no OpenGrep), skip files >100KB")
	scanCmd.Flags().Bool("staged-only", false, "only scan files in git staging area (git diff --cached)")
	scanCmd.Flags().String("fail-on", "", "exit non-zero if findings at or above this severity (critical, high, medium, low, info)")

	// Container image scanning.
	scanCmd.Flags().String("container", "", "scan a container image (reference or local .tar path)")

	// Keystore inspection: extra candidate passwords for JKS/PKCS12 unlocking.
	scanCmd.Flags().String("keystore-wordlist", "", "path to a newline-delimited password list to try (in addition to built-in defaults) when opening keystores")

	// Default-ignore controls (gh #46).
	scanCmd.Flags().Bool("no-default-ignores", false, "disable built-in default ignores (vendor/build/tool dirs, cradar's own output, minified assets)")
	scanCmd.Flags().Bool("no-gitignore", false, "do not honor .gitignore during the scan")

	// Rule lifecycle + category filter flags (docs/cli-improvements-plan.md item 1).
	scanCmd.Flags().StringSlice("category", nil, "limit findings to categories (inventory, security); repeatable")
	scanCmd.Flags().Bool("only-inventory", false, "shortcut for --category inventory")
	scanCmd.Flags().Bool("only-security", false, "shortcut for --category security")
	scanCmd.Flags().StringSlice("asset-type", nil, "keep only findings of these CBOM asset types (algorithm, protocol, certificate, related-crypto-material, library); repeatable")
	scanCmd.Flags().StringSlice("exclude-type", nil, "drop findings of these CBOM asset types; repeatable; applied after --asset-type")
	scanCmd.Flags().StringSlice("rules", nil, "explicit allowlist of rule IDs; overrides the default set")
	scanCmd.Flags().StringSlice("disable-rule", nil, "rule IDs to exclude; repeatable; trumps other include flags")
	scanCmd.Flags().StringSlice("include-rule", nil, "per-rule opt-in; repeatable; bypasses maturity and noise gates")
	scanCmd.Flags().Bool("include-experimental", false, "include rules marked maturity:experimental")
	scanCmd.Flags().Bool("include-noisy", false, "include rules marked noise_risk:high")
	scanCmd.Flags().Bool("include-deprecated", false, "silence the deprecation warning for maturity:deprecated rules")

	// Baseline suppression flags (docs/cli-improvements-plan.md item 1).
	scanCmd.Flags().String("baseline-file", baseline.DefaultFile, "path to the baseline file used for suppression")
	scanCmd.Flags().Bool("no-baseline", false, "ignore the baseline file for this run")
	scanCmd.Flags().Bool("update-baseline", false, "rewrite the baseline file from this run's security findings")

	// PDF baseline diff flag (Task 3.8): compare against a previous scan's CycloneDX JSON.
	scanCmd.Flags().String("baseline", "", "path to a previous scan's CycloneDX JSON; adds 'Changes vs Baseline' section to PDF reports")

	// Push flags (ADR-025).
	scanCmd.Flags().Bool("push", false, "upload scan results to CipherRadar portal after scan")
	scanCmd.Flags().String("project", "", "project name for portal upload (required with --push)")
	scanCmd.Flags().String("group", "", "group path for portal upload (optional)")
	scanCmd.Flags().String("api-url", "", "CipherRadar portal API URL")
	scanCmd.Flags().String("api-key", "", "API key for portal authentication (also reads CRADAR_API_KEY env)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	startedAt := time.Now()
	lg := logger()

	containerRef, _ := cmd.Flags().GetString("container")

	// Validate mutually exclusive arguments: --container vs path.
	if containerRef != "" && len(args) > 0 {
		return fmt.Errorf("--container and path argument are mutually exclusive")
	}
	if containerRef == "" && len(args) == 0 {
		return fmt.Errorf("either a path argument or --container flag is required")
	}

	// Pass 3 (YARA-X) extracts its embedded ruleset to a tempdir on first use;
	// remove it when the scan finishes rather than leaking /tmp/cradar-yara-rules-*
	// on every run (gh #82). No-op when Pass 3 didn't extract anything.
	defer yarax.CleanupEmbeddedRules()

	// Validate --asset-type / --exclude-type up front so a bad value fails
	// before the (potentially long) scan rather than after (gh #49).
	assetSel, assetErr := parseAssetTypeFlags(cmd)
	if assetErr != nil {
		return assetErr
	}

	// Record scan root for path-redaction of absolute paths in log records.
	if len(args) > 0 {
		if abs, absErr := filepath.Abs(args[0]); absErr == nil {
			lg.SetScanRoot(abs)
		}
	}
	lg.Info("scan started",
		"container", containerRef,
		"path", firstArg(args),
	)

	// Auto-sync custom rules from portal if api_url is configured (D27).
	syncCustomRules(cmd)

	// Load any user-supplied keystore password wordlist (in addition to the
	// built-in defaults) before scanning begins.
	if wl, _ := cmd.Flags().GetString("keystore-wordlist"); wl != "" {
		if data, rerr := os.ReadFile(wl); rerr == nil {
			var words []string
			for _, line := range strings.Split(string(data), "\n") {
				if w := strings.TrimRight(line, "\r"); w != "" {
					words = append(words, w)
				}
			}
			keystore.SetUserWordlist(words)
			lg.Info("keystore wordlist loaded", "path", wl, "count", len(words))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: could not read --keystore-wordlist %q: %v\n", wl, rerr)
		}
	}

	// Parse passes flag. --deep is an alias for --passes 1,2,3 (the
	// full pipeline including Pass 3 YARA-X binary scanning). --fast
	// overrides to pass 1 only.
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

	// When the user explicitly opted into Pass 3 (via --deep or via
	// --passes including 3) and yr isn't installed, hard-fail with
	// ExitToolMissing. Mirrors the runPass2 contract: a CI configured
	// for Pass 3 should not silently downgrade to "Pass 3 absent"
	// just because the binary wasn't deployed. The check uses a
	// runner constructed exactly the way the YARA-X scanner does so
	// the two stay in lockstep.
	if containsPass(passes, 3) && (cmd.Flag("deep").Changed || cmd.Flag("passes").Changed) {
		yrRunner := yarax.NewRunner()
		if yrRunner == nil || !yrRunner.Available() {
			return ExitErrorf(ExitToolMissing,
				"Pass 3 requires yara-x (yr), which was not found on PATH. Run 'cradar install-tools' or use the cradar-full binary.")
		}
	}

	// Determine scan options.
	stagedOnly, _ := cmd.Flags().GetBool("staged-only")

	// Build progress emitter for stderr heartbeat / verbose output.
	// Both flags are declared as persistent root flags (root.go).
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")
	emitter := newProgressEmitter(cmd.ErrOrStderr(), ProgressOpts{
		Quiet:          quiet,
		Verbose:        verbose,
		HeartbeatEvery: 100,
		MinInterval:    2 * time.Second,
		MinFiles:       50,
	})

	// Build scan options.
	noDefaultIgnores, _ := cmd.Flags().GetBool("no-default-ignores")
	noGitignore, _ := cmd.Flags().GetBool("no-gitignore")
	scanOpts := scanner.ScanOptions{
		Fast:             fast,
		StagedOnly:       stagedOnly,
		Progress:         emitter.WalkedFile,
		NoDefaultIgnores: noDefaultIgnores,
		NoGitignore:      noGitignore,
	}

	// Load .cradar.yml (optional) so custom_wrappers can seed the registry
	// with a CustomScanner. A missing / malformed config is a warning, not a
	// fatal — the default registry still works.
	scanCfg := loadScanConfig(cmd)

	// Resolve the external YARA-X (Pass 3) rules directory: --yara-rules-dir
	// wins over CRADAR_YARA_RULES_DIR; empty falls back to the embedded
	// ruleset (mirrors --rules-dir / CRADAR_RULES_DIR for Pass 2). When the
	// flag is explicitly set and Pass 3 is active, validate it up front and
	// hard-fail on an unusable dir rather than silently soft-skipping.
	yaraRulesDir, _ := cmd.Flags().GetString("yara-rules-dir")
	if yaraRulesDir == "" {
		yaraRulesDir = os.Getenv("CRADAR_YARA_RULES_DIR")
	}
	if cmd.Flag("yara-rules-dir").Changed && containsPass(passes, 3) {
		if err := yarax.ValidateRulesDir(yaraRulesDir); err != nil {
			return ExitErrorf(ExitToolMissing, "--yara-rules-dir: %v", err)
		}
	}

	// Resolve the external Pass-1 (AST) rules directory: --ast-rules-dir wins
	// over CRADAR_AST_RULES_DIR; empty uses the embedded tables. When the flag
	// is set explicitly and Pass 1 is active, validate up front and hard-fail
	// on an unusable dir (mirrors --rules-dir / --yara-rules-dir).
	astRulesDir, _ := cmd.Flags().GetString("ast-rules-dir")
	if astRulesDir == "" {
		astRulesDir = os.Getenv("CRADAR_AST_RULES_DIR")
	}
	if cmd.Flag("ast-rules-dir").Changed && containsPass(passes, 1) {
		if err := astrules.ValidateRulesDir(astRulesDir); err != nil {
			return ExitErrorf(ExitToolMissing, "--ast-rules-dir: %v", err)
		}
	}

	// Create scanner registry with all built-in scanners + any user-defined
	// custom wrappers from config, plus any external YARA-X and Pass-1 rules
	// overrides.
	registry := scannerinit.DefaultRegistryWithOptions(scanCfg, scannerinit.RegistryOptions{
		YaraRulesDir: yaraRulesDir,
		AstRulesDir:  astRulesDir,
	})
	if scanCfg != nil && len(scanCfg.CustomWrappers) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"Registered %d custom wrapper(s) from .cradar.yml\n",
			len(scanCfg.CustomWrappers))
	}

	var result *types.ScanResult

	// Tracks whether pass 2 actually executed (vs being skipped because
	// opengrep was absent and not required). Bug 4 uses this to emit a
	// hint when --only-inventory matches 0 findings.
	pass2Ran := false

	if containerRef != "" {
		// Container image scanning mode. Layers are materialized to a temp dir
		// and scanned through the same pipeline as a directory: Pass 1 + Pass 3
		// via the walker, Pass 2 via OpenGrep. result.PassesRun reflects the
		// passes that actually ran (gh #83).
		result, err = container.ScanImage(containerRef, registry, passes)
		if err != nil {
			return fmt.Errorf("container scan failed: %w", err)
		}
	} else {
		// Directory scanning mode.
		targetPath := args[0]

		// Bug 1: validate target exists and is a directory before walking.
		// Without this, a typo'd path returned exit 0 + empty CBOM, masking
		// broken CI configurations.
		info, statErr := os.Stat(targetPath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return ExitErrorf(ExitConfig, "scan path does not exist: %s", targetPath)
			}
			return ExitErrorf(ExitConfig, "cannot stat scan path %s: %v", targetPath, statErr)
		}
		if !info.IsDir() {
			return ExitErrorf(ExitConfig, "scan path is not a directory: %s", targetPath)
		}

		// If --staged-only, resolve staged file list from git.
		if scanOpts.StagedOnly {
			stagedFiles, gitErr := getStagedFiles(targetPath)
			if gitErr != nil {
				return fmt.Errorf("--staged-only: %w", gitErr)
			}
			scanOpts.FileList = stagedFiles
		}

		// Harvest keystore passwords from project config/source so more keystores
		// can be inventoried. No-op unless the tree contains keystores; harvested
		// values are used only as open candidates and are never reported (#92).
		if harvested := keystore.HarvestPasswords(targetPath); len(harvested) > 0 {
			keystore.SetHarvestedPasswords(harvested)
			lg.Info("harvested keystore password candidates from project", "count", len(harvested))
		}

		// Run Pass 1 scan (tree-sitter AST).
		emitter.PassStart(1, "tree-sitter", 0) // file count unknown until walk completes
		pass1Start := time.Now()
		result, err = scanner.ScanDirWithOptions(targetPath, registry, passes, scanOpts)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		emitter.PassComplete(1, "tree-sitter", time.Since(pass1Start), len(result.Findings))

		// Run Pass 2 (OpenGrep taint analysis) if requested. When the user
		// explicitly asked for pass 2 (via --deep or --passes) we hard-fail
		// with ExitToolMissing if opengrep isn't installed — the user
		// configured a check that can't actually run, and a soft skip would
		// silently downgrade the scan. When pass 2 is only running because
		// it's in the default set, we keep the legacy soft-skip behaviour.
		if containsPass(passes, 2) {
			rulesDir, _ := cmd.Flags().GetString("rules-dir")
			if rulesDir == "" {
				rulesDir = os.Getenv("CRADAR_RULES_DIR")
			}

			pass2Required := cmd.Flag("deep").Changed || cmd.Flag("passes").Changed
			emitter.PassStart(2, "opengrep", result.FilesScanned)
			pass2Start := time.Now()
			pass2Findings, pass2Err := runPass2(targetPath, rulesDir, pass2Required)
			pass2Ran = pass2Err != nil || pass2Findings != nil
			if pass2Err != nil {
				emitter.PassComplete(2, "opengrep", time.Since(pass2Start), 0)
				var ee *ExitError
				if errors.As(pass2Err, &ee) {
					return pass2Err
				}
				result.Errors = append(result.Errors, types.ScanError{
					File:    "",
					Message: fmt.Sprintf("Pass 2 error: %v", pass2Err),
				})
			} else if pass2Findings != nil {
				emitter.PassComplete(2, "opengrep", time.Since(pass2Start), len(pass2Findings))
				result.Findings = opengrep.DeduplicateFindings(result.Findings, pass2Findings)
			} else {
				// pass2Findings is nil (tool skipped)
				emitter.PassComplete(2, "opengrep", time.Since(pass2Start), 0)
			}
		}

		// Pass 3 (YARA-X binary scanning) executes as a universal *inside* the
		// Pass-1 walk above, so it has no separable timing — but it must still
		// announce itself or a completed Pass 3 looks identical to one that
		// never ran (issue #113). Emitted here (after Pass 2) so the progress
		// stream reads 1 → 2 → 3. For an explicit request (--deep / --passes 3)
		// yr availability was already enforced by the hard-fail guard above; the
		// skip branch covers the rare rules-extraction-failure path.
		//
		// The original Joern-based Pass 3 was removed per ADR-033; Pass 3 is now
		// YARA-X binary content scanning (ADR-039).
		if containsPass(passes, 3) {
			pass3Findings := 0
			for i := range result.Findings {
				if result.Findings[i].Pass == 3 {
					pass3Findings++
				}
			}
			switch {
			case !yarax.NewRunner().Available():
				emitter.PassSkipped(3, "yara-x", "yara-x (yr) not found — run 'cradar install-tools' or use cradar-full")
			case yarax.RulesDir() == "":
				emitter.PassSkipped(3, "yara-x", "no YARA-X rules available")
			default:
				emitter.PassCompleteInline(3, "yara-x", pass3Findings)
			}
		}
	}

	// Compute stable identity fingerprints for all findings (ADR-034).
	// This runs after all passes and deduplication so each finding gets
	// a deterministic fingerprint based on rule_id + file + normalized code.
	for i := range result.Findings {
		lang := fingerprint.LanguageFromPath(result.Findings[i].Location.File)
		fingerprint.ComputeFingerprint(&result.Findings[i], lang)
	}

	// Apply rule-lifecycle and category filters (Phase C). Must run AFTER
	// fingerprinting so baselined suppression (Phase D) gets stable IDs, and
	// BEFORE output writers so every format sees the same kept set.
	filterOpts, err := buildFilterOptions(cmd)
	if err != nil {
		return err
	}
	kept, filterStats := rulefilter.Apply(result.Findings, filterOpts)
	result.Findings = kept
	rulefilter.WarnDeprecated(cmd.ErrOrStderr(), filterStats, filterOpts.IncludeDeprecated)

	// Apply CBOM asset-type filters (--asset-type / --exclude-type, gh #49)
	// after rule/category filtering so the output reflects the final selection.
	result.Findings = filterByAssetType(result.Findings, assetSel)

	// Bug 4: --only-inventory with no pass 2 deterministically returns 0
	// because pass-1 AST findings don't carry rule-derived categories.
	// Surface the cause so users don't think the flag is broken.
	onlyInv, _ := cmd.Flags().GetBool("only-inventory")
	categories, _ := cmd.Flags().GetStringSlice("category")
	invRequested := onlyInv
	for _, c := range categories {
		if strings.EqualFold(c, "inventory") {
			invRequested = true
		}
	}
	if invRequested && !pass2Ran && len(result.Findings) == 0 {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"Note: inventory filter matched 0 findings; inventory rules require Pass 2 (run 'cradar install-tools' or pass --passes 1,2).")
	}

	// Apply baseline suppression (Phase D). Runs after filter+fingerprint so
	// every downstream writer and the --fail-on gate see the same reduced
	// set. --update-baseline rewrites the file from the post-filter security
	// findings and exits the gate early; --no-baseline skips suppression.
	if err := applyBaseline(cmd, result); err != nil {
		return err
	}

	// #30: stamp quantum posture (QuantumStatus + NistQuantumLevel) onto every
	// finding with a resolvable algorithm family that a scanner left unlabeled.
	// Pass-1 AST scanners label at emit time via quantum.GetInfo; Pass-2
	// (OpenGrep) findings arrive here unlabeled. Doing it once on the finalized
	// finding set — after filter/fingerprint/baseline, before any writer — gives
	// every output format (CBOM, text, SARIF, PDF, policy) identical labels.
	output.AnnotateQuantum(result)

	// Resolve crypto-library findings to concrete packages + versions + purl by
	// parsing project manifests/lockfiles (npm, Python, Maven/Gradle). Runs after
	// baseline, before any writer, so name/version/purl reach all output formats.
	enrichLibraries(cmd, result)

	// Backfill KeySize from embedded name tokens (AES-256-*) and curve identifiers
	// when individual scanners did not populate KeySize explicitly.
	keysize.Enrich(result.Findings)

	// Surface CycloneDX enum normalization violations.
	// converts the result and tallies any fall-through values that landed outside
	// the CycloneDX 1.7 closed enum sets. Writers re-run conversion independently;
	// the tally here is used only for warning emission and --strict-validate gating.
	strictValidate, _ := cmd.Flags().GetBool("strict-validate")
	_, validationTallyResult := output.ConvertScanResultWithTally(result)
	if validationTallyResult.Total > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s\n", validationTallyResult.Summary())
		if strictValidate {
			return fmt.Errorf("strict-validate: %d normalization violation(s); see warnings above", validationTallyResult.Total)
		}
	}

	// Stamp the full scan wall-clock. Both StartTime and EndTime were previously
	// set inside the scanner (ScanDir / container.ScanImage) and only spanned
	// Pass 1, so the reported "complete in" duration omitted Pass 2/3, baseline,
	// enrichment, and conversion — making a minute-long scan read as a few ms.
	// Set the true span here, before any writer (text/PDF) or the summary renders it.
	result.StartTime = startedAt
	result.EndTime = time.Now()

	// Resolve output destinations (ADR-037: repeatable --output).
	// Precedence for each destination's format: extension dispatch >
	// --format override (applied when exactly one output and --format set) >
	// cfg.default_format > built-in fallback ("cyclonedx-json").
	explicitFormat, _ := cmd.Flags().GetString("format")
	outputPaths, _ := cmd.Flags().GetStringSlice("output")
	cfgFormat := ""
	if scanCfg != nil {
		cfgFormat = scanCfg.Format
	}

	// Load baseline CBOM for PDF diff section (--baseline flag, Task 3.8).
	// baselineBOM is nil when --baseline is not set, which disables the section.
	baselineFlag, _ := cmd.Flags().GetString("baseline")
	var baselineBOM *output.BOM
	if baselineFlag != "" {
		bom, loadErr := diff.LoadBOM(baselineFlag)
		if loadErr != nil {
			return fmt.Errorf("baseline: %w", loadErr)
		}
		baselineBOM = bom
	}

	resolved, err := writeOutputs(cmd, result, outputPaths, explicitFormat, cfgFormat, baselineBOM)
	if err != nil {
		return err
	}

	// Validate output against CycloneDX 1.7 schema if requested. Runs once
	// regardless of sink count — validation is format-independent and only
	// meaningful when at least one destination produced cyclonedx-json.
	validate, _ := cmd.Flags().GetBool("validate")
	producedCycloneDX := false
	for _, r := range resolved {
		if r.Format == "cyclonedx-json" {
			producedCycloneDX = true
			break
		}
	}
	// Also check stdout sink (resolved is empty when no -o paths were given).
	if !producedCycloneDX && len(resolved) == 0 {
		stdoutFmtForValidate := output.ResolveOutputFormat("", explicitFormat, cfgFormat, output.DefaultStdoutFormat())
		if stdoutFmtForValidate == "cyclonedx-json" {
			producedCycloneDX = true
		}
	}
	if validate && producedCycloneDX {
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
				fmt.Fprintf(os.Stderr, "  %s: %s\n", e.Path, formatUserMessage(e))
				attrs := []any{
					"pointer", e.Path,
					"message", e.Message,
					"keyword", e.Keyword,
				}
				if e.Actual != "" {
					attrs = append(attrs, "actual", e.Actual)
				}
				if len(e.Expected) > 0 {
					attrs = append(attrs, "expected", e.Expected)
				}
				lg.Error("schema_validation", attrs...)
			}
			return ExitErrorf(ExitConfig, "schema validation failed with %d errors", len(valResult.Errors))
		}
		fmt.Fprintln(os.Stderr, "CycloneDX 1.7 schema validation PASSED")
		lg.Info("schema_validation_passed")
	}

	// Push scan results to portal if --push is set (ADR-025).
	pushEnabled, _ := cmd.Flags().GetBool("push")
	if pushEnabled {
		if err := runPush(cmd, result); err != nil {
			return fmt.Errorf("push failed: %w", err)
		}
	}

	// Emit the always-on final summary to stderr. Suppressed when --quiet or
	// when the text writer already printed its own summary to stdout (TTY default).
	stdoutFmt := ""
	if len(resolved) == 0 {
		// No -o paths → stdout received the output. Re-resolve the format so
		// emitFinalSummary knows whether the text writer already showed a summary.
		stdoutFmt = output.ResolveOutputFormat("", explicitFormat, cfgFormat, output.DefaultStdoutFormat())
	}
	emitFinalSummary(cmd.ErrOrStderr(), result, resolved, stdoutFmt, quiet)

	// Check --fail-on severity gate.
	failOn, _ := cmd.Flags().GetString("fail-on")
	if failOn != "" {
		if err := checkFailOn(result.Findings, failOn); err != nil {
			lg.Warn("fail-on triggered",
				"failOn", failOn,
				"findings", len(result.Findings),
				"elapsed_ms", time.Since(startedAt).Milliseconds(),
			)
			return err
		}
	}

	lg.Info("scan complete",
		"findings", len(result.Findings),
		"errors", len(result.Errors),
		"elapsed_ms", time.Since(startedAt).Milliseconds(),
	)
	return nil
}

// firstArg returns the first positional argument or an empty string. Used
// to keep log records stable even when args is empty (e.g. --container mode).
func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// writeOutputs resolves every destination (stdout or file) to a format and
// writes the scan result. With no --output paths, writes once to stdout in
// explicit/cfg/fallback order and returns an empty slice (the caller uses the
// stdoutFormat parameter of emitFinalSummary to handle the TTY/text case).
// With paths, each path's format is inferred from its extension; --format is
// only honored when there is exactly one output (otherwise it's ambiguous
// which file it applies to).
//
// baselineBOM, when non-nil, is injected into any *pdfpkg.Writer instances so
// the "Changes vs Baseline" section is rendered. The factory returns
// *pdfpkg.Writer (registered via output/pdf.init), so injectBaseline is active.
//
// Returns one ResolvedOutput per file sink (path, format, post-write size).
// The stdout-only case returns an empty slice; callers check len == 0 to know
// output went to stdout.
func writeOutputs(cmd *cobra.Command, result *types.ScanResult, paths []string, explicitFormat, cfgFormat string, baselineBOM *output.BOM) ([]ResolvedOutput, error) {
	// File sinks always fall back to cyclonedx-json (the canonical CBOM
	// artifact). Stdout falls back to text-on-TTY / cyclonedx-json-on-pipe
	// so `cradar scan ./app` prints a readable summary in a terminal and
	// writes valid JSON when redirected.
	const fileFallback = "cyclonedx-json"

	if len(paths) == 0 {
		fmtName := output.ResolveOutputFormat("", explicitFormat, cfgFormat, output.DefaultStdoutFormat())
		if err := output.ValidateFormat(fmtName); err != nil {
			return nil, ExitErrorf(ExitConfig, "%v", err)
		}
		w, err := output.WriterFactory(fmtName)
		if err != nil {
			return nil, err
		}
		injectBaseline(w, baselineBOM)
		if err := w.WriteScanResult(cmd.OutOrStdout(), result); err != nil {
			return nil, fmt.Errorf("writing output: %w", err)
		}
		// Stdout sink — no ResolvedOutput entry; caller signals this via empty slice.
		return nil, nil
	}

	// --format only applies to a single output; ambiguous with multiple sinks.
	perPathExplicit := ""
	if len(paths) == 1 {
		perPathExplicit = explicitFormat
	} else if explicitFormat != "" {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"WARNING: --format %q ignored: multiple --output paths provided, format is inferred per file extension\n",
			explicitFormat)
	}

	var resolved []ResolvedOutput
	for _, p := range paths {
		fmtName := output.ResolveOutputFormat(p, perPathExplicit, cfgFormat, fileFallback)
		if err := output.ValidateFormat(fmtName); err != nil {
			return nil, ExitErrorf(ExitConfig, "%v (path: %s)", err, p)
		}
		w, err := output.WriterFactory(fmtName)
		if err != nil {
			return nil, err
		}
		injectBaseline(w, baselineBOM)
		f, err := os.Create(p)
		if err != nil {
			return nil, fmt.Errorf("cannot create output file %s: %w", p, err)
		}
		if err := w.WriteScanResult(f, result); err != nil {
			f.Close()
			return nil, fmt.Errorf("writing %s: %w", p, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("closing %s: %w", p, err)
		}
		stat, _ := os.Stat(p)
		var size int64
		if stat != nil {
			size = stat.Size()
		}
		resolved = append(resolved, ResolvedOutput{Path: p, Format: fmtName, Size: size})
	}
	return resolved, nil
}

// injectBaseline sets the baseline BOM on a *pdfpkg.Writer if the writer is
// that concrete type. This is a no-op for all other writer implementations.
func injectBaseline(w output.Writer, baselineBOM *output.BOM) {
	if baselineBOM == nil {
		return
	}
	if pw, ok := w.(*pdfpkg.Writer); ok {
		pw.Opts.Baseline = baselineBOM
	}
}

// formatUserMessage renders a ValidationError for the human-facing stderr
// line. When the underlying schema error exposes enum/const/required hints
// we append them so the message is actionable ("expected one of [aes, rsa,
// ...]; got concatkdf") rather than a bare "does not match schema".
func formatUserMessage(e validation.ValidationError) string {
	base := e.Message
	switch e.Keyword {
	case "enum":
		if len(e.Expected) > 0 {
			return fmt.Sprintf("%s (expected one of [%s]; got %s)",
				base, strings.Join(trimForMessage(e.Expected, 8), ", "), e.Actual)
		}
	case "const":
		if len(e.Expected) > 0 {
			return fmt.Sprintf("%s (expected %s; got %s)", base, e.Expected[0], e.Actual)
		}
	case "type":
		if len(e.Expected) > 0 {
			return fmt.Sprintf("%s (expected type %s; got %s)",
				base, strings.Join(e.Expected, "|"), e.Actual)
		}
	case "required":
		if len(e.Expected) > 0 {
			return fmt.Sprintf("%s (missing: %s)", base, strings.Join(e.Expected, ", "))
		}
	}
	return base
}

func trimForMessage(s []string, maxN int) []string {
	if len(s) <= maxN {
		return s
	}
	out := make([]string, 0, maxN+1)
	out = append(out, s[:maxN]...)
	out = append(out, fmt.Sprintf("... %d more", len(s)-maxN))
	return out
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
// When required=true and OpenGrep is missing, returns an ExitToolMissing
// error so CI distinguishes "tool not installed" (exit 4) from "findings
// above threshold" (exit 1). When required=false, emits the legacy
// warning and returns nil findings so default scans still work without
// opengrep installed.
func runPass2(target, rulesDir string, required bool) ([]types.Finding, error) {
	runner := opengrep.NewRunner()
	if runner == nil || !runner.Available() {
		if required {
			return nil, ExitErrorf(ExitToolMissing,
				"Pass 2 requires opengrep, which was not found on PATH. Run 'cradar install-tools' or use the cradar-full binary.")
		}
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
// checkFailOn aggregates every finding at or above the --fail-on threshold
// and returns a single grouped ExitError listing per-severity counts plus
// the first 5 offenders as concrete examples. Earlier versions stopped at
// the first hit, silently dropping the remaining offenders — confusing on
// large codebases where the user wants the full picture in one pass.
func checkFailOn(findings []types.Finding, failOn string) error {
	threshold, ok := scanSeverityRank[types.Severity(strings.ToLower(failOn))]
	if !ok {
		return ExitErrorf(ExitConfig, "invalid --fail-on severity: %q (valid: critical, high, medium, low, info)", failOn)
	}

	type offender struct {
		name     string
		severity types.Severity
		location string
	}
	var hits []offender
	countBySeverity := map[types.Severity]int{}
	for _, f := range findings {
		rank, ok := scanSeverityRank[f.Severity]
		if !ok {
			continue
		}
		if rank < threshold {
			continue
		}
		countBySeverity[f.Severity]++
		hits = append(hits, offender{
			name:     f.Name,
			severity: f.Severity,
			location: fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine),
		})
	}
	if len(hits) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("scan failed: %d finding(s) at or above %s", len(hits), failOn))
	// Per-severity counts in fixed order so output is stable.
	for _, s := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow} {
		if n := countBySeverity[s]; n > 0 {
			sb.WriteString(fmt.Sprintf(" [%s: %d]", s, n))
		}
	}
	sb.WriteString("\n  examples:")
	shown := hits
	if len(shown) > 5 {
		shown = shown[:5]
	}
	for _, o := range shown {
		sb.WriteString(fmt.Sprintf("\n    - %s (%s) at %s", o.name, o.severity, o.location))
	}
	if len(hits) > 5 {
		sb.WriteString(fmt.Sprintf("\n    ... %d more", len(hits)-5))
	}
	return &ExitError{Code: ExitFindings, Err: fmt.Errorf("%s", sb.String())}
}

// buildFilterOptions resolves rule-lifecycle filter flags + .cradar.yml
// defaults into rulefilter.Options. Precedence: CLI flag (if Changed) >
// .cradar.yml rule_filters > defaults.
//
// --only-inventory and --only-security are sugar over --category:
//   - both set (or neither) → no category restriction
//   - only one → that single category
func buildFilterOptions(cmd *cobra.Command) (rulefilter.Options, error) {
	cfg := &config.Config{}
	if configPath, _ := cmd.Flags().GetString("config"); configPath != "" {
		loaded, err := config.LoadConfig(configPath)
		if err != nil {
			// Non-fatal — filters still work with flag-only input.
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: rule filter: could not load %s: %v\n", configPath, err)
		} else if loaded != nil {
			cfg = loaded
		}
	}

	opts := rulefilter.Options{}
	if cfg.RuleFilters != nil {
		rf := cfg.RuleFilters
		opts.Categories = toCategories(rf.Categories)
		opts.Rules = append([]string(nil), rf.Rules...)
		opts.DisabledRules = append([]string(nil), rf.DisabledRules...)
		opts.IncludeRules = append([]string(nil), rf.IncludeRules...)
		opts.IncludeExperimental = rf.IncludeExperimental
		opts.IncludeNoisy = rf.IncludeNoisy
		opts.IncludeDeprecated = rf.IncludeDeprecated
	}

	// CLI flags override config. Only overwrite when flag was explicitly set
	// (Changed) so that an unset flag doesn't clobber a config value.
	if cmd.Flag("category").Changed {
		cats, _ := cmd.Flags().GetStringSlice("category")
		opts.Categories = toCategories(cats)
	}
	onlyInv, _ := cmd.Flags().GetBool("only-inventory")
	onlySec, _ := cmd.Flags().GetBool("only-security")
	if onlyInv && !onlySec {
		opts.Categories = []types.Category{types.CategoryInventory}
	} else if onlySec && !onlyInv {
		opts.Categories = []types.Category{types.CategorySecurity}
	}
	// Both/neither → leave Categories as-is (both or unrestricted).

	if cmd.Flag("rules").Changed {
		v, _ := cmd.Flags().GetStringSlice("rules")
		opts.Rules = v
	}
	if cmd.Flag("disable-rule").Changed {
		v, _ := cmd.Flags().GetStringSlice("disable-rule")
		opts.DisabledRules = v
	}
	if cmd.Flag("include-rule").Changed {
		v, _ := cmd.Flags().GetStringSlice("include-rule")
		opts.IncludeRules = v
	}
	if cmd.Flag("include-experimental").Changed {
		opts.IncludeExperimental, _ = cmd.Flags().GetBool("include-experimental")
	}
	if cmd.Flag("include-noisy").Changed {
		opts.IncludeNoisy, _ = cmd.Flags().GetBool("include-noisy")
	}
	if cmd.Flag("include-deprecated").Changed {
		opts.IncludeDeprecated, _ = cmd.Flags().GetBool("include-deprecated")
	}

	// Validate category values so a typo fails loudly instead of silently
	// dropping all findings.
	for _, c := range opts.Categories {
		if c != types.CategoryInventory && c != types.CategorySecurity {
			return rulefilter.Options{}, ExitErrorf(ExitConfig, "invalid --category value %q (valid: inventory, security)", c)
		}
	}
	return opts, nil
}

// toCategories converts raw string values to types.Category. Unknown strings
// are passed through so validation can flag them; empty entries are dropped.
func toCategories(xs []string) []types.Category {
	if len(xs) == 0 {
		return nil
	}
	out := make([]types.Category, 0, len(xs))
	for _, s := range xs {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		out = append(out, types.Category(s))
	}
	return out
}

// loadScanConfig reads .cradar.yml (path from --config) for scan-time uses
// — currently custom_wrappers seeding. Returns nil when no config path is
// set or the file cannot be read; a nil return short-circuits all config-
// driven features without surfacing an error (config is always optional).
func loadScanConfig(cmd *cobra.Command) *config.Config {
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		return nil
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"WARNING: could not load config %s: %v\n", configPath, err)
		return nil
	}
	return cfg
}

// enrichLibraries resolves each finding's coarse cbom-library hint to a concrete
// package + version + purl using project manifests/lockfiles, stashing the
// result on the finding's CryptoProperties for the converter to emit. It is a
// best-effort pass: no manifests (or a non-directory target, e.g. a container
// scan) simply means library names surface without versions.
func enrichLibraries(cmd *cobra.Command, result *types.ScanResult) {
	root := result.Target
	if root == "" {
		return
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return
	}
	ix, _ := deps.Build(root)
	unresolved := 0
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.Properties.Library == "" {
			continue
		}
		// Pass-3 (YARA-X binary) library detections carry their own version from
		// the binary; resolving them against the project's *source* manifests
		// would attach a wrong purl (e.g. a binary OpenSSL matching the repo's
		// Rust openssl crate). Leave binary findings to their YARA-derived version.
		if f.Pass == 3 {
			continue
		}
		// Finding paths are root-relative; rejoin so nearest-ancestor manifest
		// resolution shares the index's coordinate space.
		fromFile := filepath.Join(root, f.Location.File)
		p, ok := deps.ResolveLibrary(ix, f.Properties.Library, f.Location.Snippet, fromFile)
		if !ok {
			continue
		}
		f.Properties.LibraryGroup = p.Group
		f.Properties.LibraryVersion = p.Version
		f.Properties.LibraryPurl = deps.BuildPurl(p)
		if p.Version == "" {
			unresolved++
		}
	}
	if unresolved > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"NOTE: %d crypto library finding(s) detected without a resolved version (no matching manifest pin)\n", unresolved)
	}
}

// applyBaseline handles baseline load/apply/update for a scan run. On success
// it mutates result.Findings to the kept subset (removing any suppressed
// security finding). --update-baseline rewrites the baseline from this run's
// eligible findings; --no-baseline short-circuits suppression. Stale entries
// and suppression counts are reported on stderr so CI logs surface drift.
func applyBaseline(cmd *cobra.Command, result *types.ScanResult) error {
	path, _ := cmd.Flags().GetString("baseline-file")
	noBaseline, _ := cmd.Flags().GetBool("no-baseline")
	update, _ := cmd.Flags().GetBool("update-baseline")

	if update {
		b, skipped := baseline.BuildFromSecurityFindings(result.Findings, Version)
		if err := baseline.Save(path, b); err != nil {
			return fmt.Errorf("writing baseline: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(),
			"Baseline written to %s: %d fingerprint(s)", path, len(b.Fingerprints))
		if skipped > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(),
				" (%d finding(s) skipped — missing fingerprint)", skipped)
		}
		fmt.Fprintln(cmd.ErrOrStderr())
		return nil
	}

	if noBaseline {
		return nil
	}

	b, err := baseline.Load(path)
	if err != nil {
		return err
	}
	if b == nil {
		return nil
	}

	res := baseline.Apply(result.Findings, b)
	result.Findings = res.Kept

	if res.SuppressedCount > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"Baseline suppressed %d finding(s) (from %s)\n", res.SuppressedCount, path)
	}
	if len(res.Stale) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"Baseline has %d stale entry(ies) — code may have been fixed or rules removed. Run with --update-baseline to clean up.\n",
			len(res.Stale))
	}
	return nil
}

// syncCustomRules attempts to download custom rules from the portal before
// scanning. Requires api_url in .cradar.yml config. On failure, logs a
// warning and continues with embedded + cached rules.
func syncCustomRules(cmd *cobra.Command) {
	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.LoadConfig(configPath)
	if err != nil || cfg == nil {
		return
	}

	apiURL, _ := cmd.Flags().GetString("api-url")
	if apiURL == "" {
		apiURL = cfg.APIURL
	}
	if apiURL == "" {
		return
	}

	apiKey, _ := cmd.Flags().GetString("api-key")
	if apiKey == "" {
		apiKey = os.Getenv("CRADAR_API_KEY")
	}
	apiKey = cfg.ResolveAPIKey(apiKey)
	if apiKey == "" {
		return
	}

	if err := rules.SyncRules(apiURL, apiKey); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: custom rule sync failed: %v\n", err)
	}
}
