package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/ignore"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	logpkg "github.com/nk-sentinel/cipherradar/cli/pkg/log"
)

// isCycloneDXOrSARIF checks the first ~100 bytes of JSON content for signatures
// of CycloneDX BOM output or SARIF scanner output. These are skipped to avoid
// the regex scanner matching thousands of algorithm names in its own output.
func isCycloneDXOrSARIF(content []byte) bool {
	// Only inspect the first 512 bytes for efficiency
	probe := content
	if len(probe) > 512 {
		probe = probe[:512]
	}
	// CycloneDX: contains both "bomFormat" and "CycloneDX"
	if bytes.Contains(probe, []byte(`"bomFormat"`)) && bytes.Contains(probe, []byte(`"CycloneDX"`)) {
		return true
	}
	// SARIF: contains both "$schema" and "sarif"
	if bytes.Contains(probe, []byte(`"$schema"`)) && bytes.Contains(probe, []byte("sarif")) {
		return true
	}
	return false
}

// scanJob represents a single file to be scanned by the worker pool.
type scanJob struct {
	path       string
	relPath    string
	content    []byte
	scanner    Scanner   // extension-matched scanner, or nil
	universals []Scanner // universal scanners (only set when scanner is nil)
}

// scanJobResult holds the output from scanning a single file.
type scanJobResult struct {
	findings []types.Finding
	errors   []types.ScanError
	scanned  bool
	lang     string // scanner name (or empty for universal-only files)
	relPath  string // relative path, echoed back for the Progress callback
}

// ScanOptions controls optional scanning behavior.
type ScanOptions struct {
	// Fast limits scanning to Pass 1 only and skips files >100KB.
	Fast bool
	// StagedOnly restricts scanning to files listed in FileList.
	StagedOnly bool
	// FileList is the explicit set of relative file paths to scan (used with StagedOnly).
	FileList []string

	// NoDefaultIgnores disables the built-in default ignore set (gh #46).
	NoDefaultIgnores bool
	// NoGitignore disables honoring .gitignore during the walk.
	NoGitignore bool

	// Progress, if non-nil, is invoked once per scanned file with the
	// detected language (may be empty if no extension match) and the
	// relative path. Used for stderr heartbeat / verbose output.
	// Implementation note: invoked from the result-collector goroutine,
	// not the worker pool, so callers do not need their own mutex.
	Progress func(lang, path string)
}

// maxFastFileSize is the maximum file size (in bytes) scanned when --fast is set.
const maxFastFileSize = 100 * 1024 // 100KB

// ScanDir walks a directory tree, dispatches each file to the appropriate scanner
// using a concurrent worker pool, and returns the aggregated scan result.
// Output is deterministic: findings are sorted by file path then line number.
func ScanDir(root string, registry *Registry, passes []int) (*types.ScanResult, error) {
	return ScanDirWithOptions(root, registry, passes, ScanOptions{})
}

// ScanDirWithOptions is like ScanDir but accepts additional scanning options
// for fast mode and staged-only filtering.
func ScanDirWithOptions(root string, registry *Registry, passes []int, opts ScanOptions) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:    root,
		StartTime: time.Now(),
		PassesRun: passes,
	}

	// Build an allow-set for staged-only mode.
	var allowSet map[string]bool
	if opts.StagedOnly && len(opts.FileList) > 0 {
		allowSet = make(map[string]bool, len(opts.FileList))
		for _, f := range opts.FileList {
			allowSet[f] = true
		}
	}

	// Build the ignore matcher (built-in defaults + .gitignore + .cradarignore),
	// gh #46. Default ignores and .gitignore can be disabled via opts.
	// When Pass 3 (YARA-X binary scanning) is active, build-output dirs must
	// remain scannable — that is where compiled binaries live.
	ignoreMatcher := ignore.New(root, !opts.NoDefaultIgnores, !opts.NoGitignore, containsPassInt(passes, 3))

	// Phase 1: Walk the directory tree and collect scan jobs.
	// The walk itself is sequential (os.WalkDir is not concurrent-safe).
	var jobs []scanJob
	var walkErrors []types.ScanError

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			walkErrors = append(walkErrors, types.ScanError{
				File:    path,
				Message: err.Error(),
			})
			return nil // continue walking
		}

		if d.IsDir() {
			// Skip non-source directories (built-in defaults + .gitignore +
			// .cradarignore). The scan root itself is never skipped.
			if path == root {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if ignoreMatcher.SkipDir(rel, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, _ := filepath.Rel(root, path)

		// In staged-only mode, skip files not in the allow set.
		if allowSet != nil && !allowSet[relPath] {
			return nil
		}

		// Apply ignore rules (built-in defaults + .gitignore + .cradarignore).
		if ignoreMatcher.SkipFile(relPath) {
			return nil
		}

		ext := DetectLanguage(path)

		// Always skip binary and dedicated scanner output by extension.
		switch strings.ToLower(ext) {
		case ".sarif":
			return nil // .sarif extension is always scanner output
		case ".pdf":
			return nil // binary, never source
		}

		s := registry.ForExtension(ext)
		universals := registry.Universals()

		if s == nil && len(universals) == 0 {
			return nil // no scanner for this file type
		}

		// In fast mode, skip files larger than 100KB.
		if opts.Fast {
			info, statErr := d.Info()
			if statErr == nil && info.Size() > maxFastFileSize {
				return nil
			}
		}

		content, err := os.ReadFile(path)
		if err != nil {
			walkErrors = append(walkErrors, types.ScanError{
				File:    path,
				Message: err.Error(),
			})
			return nil
		}

		// For .json files, only skip CycloneDX and SARIF output files.
		// Config JSON (Terraform, k8s manifests, etc.) should be scanned.
		if strings.ToLower(ext) == ".json" {
			if isCycloneDXOrSARIF(content) {
				return nil
			}
		}

		job := scanJob{
			path:    path,
			relPath: relPath,
			content: content,
			scanner: s,
		}
		// Universals are assigned to every job, with two filters applied:
		// (a) Pass-aware universals are skipped when their pass isn't in
		//     the active --passes selection (gates YARA-X behind --passes 3
		//     so default scans don't pay the Pass-3 cost).
		// (b) The universal's own ScanFile() decides whether to fire on
		//     this specific path (e.g. YARA-X soft-skips source files;
		//     regex soft-skips binaries via a NUL probe).
		//
		// Previously universals only ran on files without a language
		// scanner — that prevented YARA-X from firing on .jar / .class /
		// .so binaries because the native binary/jar/wheel scanners had
		// already claimed those extensions. Filtering by pass + path
		// inside each universal is more accurate.
		job.universals = filterUniversalsForPasses(universals, passes)

		jobs = append(jobs, job)
		return nil
	})

	// Phase 2: Process jobs concurrently using a worker pool.
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // cap to avoid excessive memory usage
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	results := make([]scanJobResult, len(jobs))

	var wg sync.WaitGroup
	jobCh := make(chan int, len(jobs))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				job := jobs[idx]
				var findings []types.Finding
				var errs []types.ScanError
				scanned := false

				lg := logpkg.Get()

				// Run extension-matched scanner
				if job.scanner != nil {
					scannerStart := time.Now()
					lg.ScannerStart(job.scanner.Name(), job.relPath)
					f, scanErr := job.scanner.ScanFile(job.relPath, job.content)
					lg.ScannerComplete(job.scanner.Name(), len(f), time.Since(scannerStart))
					if scanErr != nil {
						errs = append(errs, types.ScanError{
							File:    job.relPath,
							Message: scanErr.Error(),
						})
					} else {
						for _, fnd := range f {
							lg.FindingEmitted(job.scanner.Name(), fnd.RuleID, string(fnd.Severity), fnd.Location.File, fnd.Location.Snippet)
						}
						findings = append(findings, f...)
					}
					scanned = true
				}

				// Run universal scanners on every job regardless of whether
				// a language scanner already claimed the file. Universals
				// self-gate via ScanFile (regex via NUL probe / extension
				// list; YARA-X via its supportedExtensions check); the
				// walker no longer second-guesses that decision. Pass-3
				// scanners were already filtered out at job-assembly time
				// when --passes doesn't include 3.
				for _, us := range job.universals {
					scannerStart := time.Now()
					lg.ScannerStart(us.Name(), job.relPath)
					f, scanErr := us.ScanFile(job.relPath, job.content)
					lg.ScannerComplete(us.Name(), len(f), time.Since(scannerStart))
					if scanErr != nil {
						errs = append(errs, types.ScanError{
							File:    job.relPath,
							Message: scanErr.Error(),
						})
						continue
					}
					for _, fnd := range f {
						lg.FindingEmitted(us.Name(), fnd.RuleID, string(fnd.Severity), fnd.Location.File, fnd.Location.Snippet)
					}
					findings = append(findings, f...)
					scanned = true
				}

				// Derive language label from the matched scanner name.
				// Universal-only files have no language scanner, so lang stays "".
				lang := ""
				if job.scanner != nil {
					lang = job.scanner.Name()
				}
				results[idx] = scanJobResult{
					findings: findings,
					errors:   errs,
					scanned:  scanned,
					lang:     lang,
					relPath:  job.relPath,
				}
			}
		}()
	}

	// Enqueue all jobs
	for i := range jobs {
		jobCh <- i
	}
	close(jobCh)

	// Wait for all workers to finish
	wg.Wait()

	// Phase 3: Collect results.
	result.Errors = append(result.Errors, walkErrors...)

	filesScanned := 0
	for _, r := range results {
		result.Findings = append(result.Findings, r.findings...)
		result.Errors = append(result.Errors, r.errors...)
		if r.scanned {
			filesScanned++
			if opts.Progress != nil {
				opts.Progress(r.lang, r.relPath)
			}
		}
	}
	result.FilesScanned = filesScanned

	// Sort findings for deterministic output: by file path, then by start line.
	sort.Slice(result.Findings, func(i, j int) bool {
		fi, fj := result.Findings[i], result.Findings[j]
		if fi.Location.File != fj.Location.File {
			return fi.Location.File < fj.Location.File
		}
		return fi.Location.StartLine < fj.Location.StartLine
	})

	// Reassign sequential finding IDs after sorting so that downstream
	// consumers (e.g. CycloneDX converter, which sorts by BOMRef = ID)
	// produce deterministic output regardless of worker scheduling order.
	for i := range result.Findings {
		result.Findings[i].ID = fmt.Sprintf("FIND-%d", i+1)
	}

	result.EndTime = time.Now()

	if err != nil {
		return result, err
	}
	return result, nil
}

// filterUniversalsForPasses returns the subset of universals whose
// declared pass is included in the active passes selection. A universal
// that doesn't implement PassAware is always included — same effective
// behaviour as before this filter existed.
//
// The walker calls this once per file (cheap: 3 universals max, single
// type assertion each) rather than at registry-build time so a future
// --only-pass-3 mode can flip the filter without rebuilding the
// registry.
func filterUniversalsForPasses(universals []Scanner, passes []int) []Scanner {
	if len(universals) == 0 {
		return universals
	}
	out := make([]Scanner, 0, len(universals))
	for _, u := range universals {
		if pa, ok := u.(PassAware); ok {
			p := pa.Pass()
			if p > 0 && !containsPassInt(passes, p) {
				continue
			}
		}
		out = append(out, u)
	}
	return out
}

// containsPassInt mirrors cmd.containsPass at the scanner level so
// walker can do the filter without a package cycle (cmd imports
// scanner). Kept package-private to avoid duplicating the public
// surface area.
func containsPassInt(passes []int, p int) bool {
	for _, x := range passes {
		if x == p {
			return true
		}
	}
	return false
}
