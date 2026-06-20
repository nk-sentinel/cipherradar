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
var defaultSkipDirs = map[string]bool{
	// VCS
	".git": true,
	// Dependencies / vendor
	"node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"site-packages": true, "bower_components": true, "Pods": true,
	// Build output
	"target": true, "build": true, "dist": true, "out": true,
	"bin": true, "obj": true, "__pycache__": true,
	// Other tools' working directories
	".scannerwork": true, ".gradle": true, ".terraform": true,
	".pytest_cache": true, ".idea": true, ".vscode": true,
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
	useDefaults bool
	git         *gitignore.GitIgnore // compiled root .gitignore (nil if absent/disabled)
	cradar      *gitignore.GitIgnore // compiled root .cradarignore (nil if absent)
}

// New builds a Matcher for a scan rooted at root. useDefaults toggles the
// built-in default ignores; useGitignore toggles honoring .gitignore. A
// .cradarignore at root is always honored when present.
func New(root string, useDefaults, useGitignore bool) *Matcher {
	m := &Matcher{useDefaults: useDefaults}
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
	if m.useDefaults && defaultSkipDirs[name] {
		return true
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
