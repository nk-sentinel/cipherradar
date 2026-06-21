// Package ignore decides which files and directories a scan should skip. It
// layers, in increasing precedence:
//
//  1. Built-in defaults — VCS/vendor/build/tool-workdirs + cradar's own output
//     and minified/generated assets (gh #46). These are the "real fix" and need
//     no configuration.
//  2. .gitignore — honored by default (disable with --no-gitignore), so dirs a
//     project already ignores (build/, dist/, …) are skipped for free.
//  3. .cradarignore — project-specific scan ignores (gitignore syntax).
//
// Config files, certificate/key material, and binaries are deliberately NOT in
// the built-in defaults so they remain scannable.
package ignore

import (
	"path/filepath"

	gitignore "github.com/sabhiram/go-gitignore"
)

// defaultSkipDirs are directory names skipped by the built-in defaults.
// vendorSkipDirs are always skipped (VCS, dependencies/vendor, tool workdirs) —
// they never contain first-party artifacts worth scanning, including under Pass 3.
var vendorSkipDirs = map[string]bool{
	// VCS
	".git": true,
	// Dependencies / vendor
	"node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"site-packages": true, "bower_components": true, "Pods": true, "__pycache__": true,
	// Other tools' working directories
	".scannerwork": true, ".gradle": true, ".terraform": true,
	".pytest_cache": true, ".idea": true, ".vscode": true,
}

// buildOutputDirs are skipped for source passes but NOT when Pass 3 (YARA-X
// binary scanning) is enabled — compiled binaries live exactly here, so skipping
// them would make `--deep` silently miss its targets (gh #74-adjacent).
var buildOutputDirs = map[string]bool{
	"target": true, "build": true, "dist": true, "out": true,
	"bin": true, "obj": true,
}

// defaultFileGlobs are file-name patterns skipped by the built-in defaults:
// cradar's own output and minified/generated assets.
var defaultFileGlobs = []string{
	"*.min.js", "*.bundle.js", "*.map",
	".cradar-baseline.json", ".cradarignore",
}

// Matcher decides whether paths are ignored. The zero value ignores nothing;
// construct with New.
type Matcher struct {
	useDefaults  bool
	scanBinaries bool                 // Pass 3 active: do not skip build-output dirs
	git          *gitignore.GitIgnore // compiled root .gitignore (nil if absent/disabled)
	cradar       *gitignore.GitIgnore // compiled root .cradarignore (nil if absent)
}

// New builds a Matcher for a scan rooted at root. useDefaults toggles the
// built-in default ignores; useGitignore toggles honoring .gitignore. A
// .cradarignore at root is always honored when present.
//
// scanBinaries signals that Pass 3 (YARA-X binary scanning) is active; when
// true, build-output directories (target/build/dist/out/bin/obj) are NOT
// pruned by the built-in defaults, because that is where compiled binaries
// live. Vendor/dependency/tool dirs are always pruned regardless.
func New(root string, useDefaults, useGitignore, scanBinaries bool) *Matcher {
	m := &Matcher{useDefaults: useDefaults, scanBinaries: scanBinaries}
	if useGitignore {
		if gi, err := gitignore.CompileIgnoreFile(filepath.Join(root, ".gitignore")); err == nil {
			m.git = gi
		}
	}
	if ci, err := gitignore.CompileIgnoreFile(filepath.Join(root, ".cradarignore")); err == nil {
		m.cradar = ci
	}
	return m
}

// SkipDir reports whether a directory (relPath relative to the scan root, name
// its base) should be skipped, pruning the whole subtree.
func (m *Matcher) SkipDir(relPath, name string) bool {
	if m.useDefaults {
		if vendorSkipDirs[name] {
			return true
		}
		// Build-output dirs are only pruned when Pass 3 is NOT scanning
		// binaries — otherwise --deep would silently miss its targets.
		if !m.scanBinaries && buildOutputDirs[name] {
			return true
		}
	}
	// gitignore-style matchers expect a trailing slash to match dir rules.
	rel := filepath.ToSlash(relPath)
	if m.git != nil && (m.git.MatchesPath(rel) || m.git.MatchesPath(rel+"/")) {
		return true
	}
	if m.cradar != nil && (m.cradar.MatchesPath(rel) || m.cradar.MatchesPath(rel+"/")) {
		return true
	}
	return false
}

// SkipFile reports whether a file (relPath relative to the scan root) should be
// skipped.
func (m *Matcher) SkipFile(relPath string) bool {
	rel := filepath.ToSlash(relPath)
	base := filepath.Base(rel)
	if m.useDefaults {
		for _, g := range defaultFileGlobs {
			if ok, _ := filepath.Match(g, base); ok {
				return true
			}
		}
	}
	if m.git != nil && m.git.MatchesPath(rel) {
		return true
	}
	if m.cradar != nil && m.cradar.MatchesPath(rel) {
		return true
	}
	return false
}
