package deps

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Index holds resolved dependency versions discovered across a project tree,
// keyed by the directory of the manifest they came from. Lookups use
// nearest-ancestor resolution so a finding resolves against the closest
// enclosing manifest (monorepo-friendly).
type Index struct {
	// byDir[manifestDir][ecosystem][normalizedName] = Package
	byDir map[string]map[Ecosystem]map[string]Package
	dirs  []string // manifest dirs, longest first (for nearest-ancestor)
}

// Warning describes a non-fatal problem encountered while building the index.
type Warning struct {
	Path string
	Err  error
}

// skipDirs are directories never descended into when discovering manifests.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true,
	"dist": true, "build": true, ".idea": true, ".vscode": true,
}

// maxManifestBytes caps the size of a manifest file we will parse.
const maxManifestBytes = 8 << 20 // 8 MiB

// Build walks root once and parses every recognized manifest/lockfile into an
// Index. It never returns a fatal error for a malformed individual manifest —
// those are collected as warnings.
func Build(root string) (*Index, []Warning) {
	ix := &Index{byDir: make(map[string]map[Ecosystem]map[string]Package)}
	var warnings []Warning

	add := func(dir string, pkgs []Package, err error, path string) {
		if err != nil {
			warnings = append(warnings, Warning{Path: path, Err: err})
			return
		}
		for _, p := range pkgs {
			ix.put(dir, p)
		}
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxManifestBytes {
			return nil
		}
		dir := filepath.Dir(path)
		switch strings.ToLower(d.Name()) {
		case "package-lock.json":
			pkgs, perr := parseNpmLock(path)
			add(dir, pkgs, perr, path)
		case "package.json":
			pkgs, perr := parsePackageJSON(path)
			add(dir, pkgs, perr, path)
		case "requirements.txt":
			pkgs, perr := parseRequirementsTxt(path)
			add(dir, pkgs, perr, path)
		case "poetry.lock":
			pkgs, perr := parsePoetryLock(path)
			add(dir, pkgs, perr, path)
		case "pipfile.lock":
			pkgs, perr := parsePipfileLock(path)
			add(dir, pkgs, perr, path)
		case "pom.xml":
			pkgs, perr := parsePomXML(path)
			add(dir, pkgs, perr, path)
		case "gradle.lockfile":
			pkgs, perr := parseGradleLockfile(path)
			add(dir, pkgs, perr, path)
		case "build.gradle", "build.gradle.kts":
			pkgs, perr := parseBuildGradle(path)
			add(dir, pkgs, perr, path)
		case "cargo.lock":
			pkgs, perr := parseCargoLock(path)
			add(dir, pkgs, perr, path)
		case "gemfile.lock":
			pkgs, perr := parseGemfileLock(path)
			add(dir, pkgs, perr, path)
		case "go.mod":
			pkgs, perr := parseGoMod(path)
			add(dir, pkgs, perr, path)
		case "pubspec.lock":
			pkgs, perr := parsePubspecLock(path)
			add(dir, pkgs, perr, path)
		}
		return nil
	})

	ix.finalize()
	return ix, warnings
}

// put inserts a package, preferring an entry that carries a version over one
// that does not (lockfiles win over declaration-only manifests).
func (ix *Index) put(dir string, p Package) {
	if p.Name == "" {
		return
	}
	eco := ix.byDir[dir]
	if eco == nil {
		eco = make(map[Ecosystem]map[string]Package)
		ix.byDir[dir] = eco
	}
	names := eco[p.Ecosystem]
	if names == nil {
		names = make(map[string]Package)
		eco[p.Ecosystem] = names
	}
	key := normalizeName(p.Ecosystem, p.Name)
	if existing, ok := names[key]; ok {
		// Prefer a resolved version; otherwise keep direct-dependency status.
		if existing.Version != "" && p.Version == "" {
			if p.Direct {
				existing.Direct = true
				names[key] = existing
			}
			return
		}
		if p.Direct {
			p.Direct = true
		}
	}
	names[key] = p
}

func (ix *Index) finalize() {
	ix.dirs = ix.dirs[:0]
	for dir := range ix.byDir {
		ix.dirs = append(ix.dirs, dir)
	}
	// Longest path first so nearest-ancestor wins.
	for i := 0; i < len(ix.dirs); i++ {
		for j := i + 1; j < len(ix.dirs); j++ {
			if len(ix.dirs[j]) > len(ix.dirs[i]) {
				ix.dirs[i], ix.dirs[j] = ix.dirs[j], ix.dirs[i]
			}
		}
	}
}

// Resolve looks up a package by ecosystem and name, starting from the manifest
// nearest to fromFile and walking up to the project root. fromFile may be
// absolute or relative to the same root passed to Build.
func (ix *Index) Resolve(eco Ecosystem, name, fromFile string) (Package, bool) {
	if p, ok := ix.ResolveAncestor(eco, name, fromFile); ok {
		return p, true
	}
	// Fallback: any manifest in the project declaring the package.
	key := normalizeName(eco, name)
	for _, dir := range ix.dirs {
		if p, ok := ix.lookup(dir, eco, key); ok {
			return p, true
		}
	}
	return Package{}, false
}

// ResolveAncestor is like Resolve but only matches a manifest that is an
// ancestor of fromFile (no cross-tree fallback). Lets callers prefer the file's
// own ecosystem when the same package name exists in multiple ecosystems.
func (ix *Index) ResolveAncestor(eco Ecosystem, name, fromFile string) (Package, bool) {
	key := normalizeName(eco, name)
	fromDir := filepath.Dir(fromFile)
	for _, dir := range ix.dirs {
		if !isAncestorDir(dir, fromDir) {
			continue
		}
		if p, ok := ix.lookup(dir, eco, key); ok {
			return p, true
		}
	}
	return Package{}, false
}

func (ix *Index) lookup(dir string, eco Ecosystem, key string) (Package, bool) {
	if names := ix.byDir[dir][eco]; names != nil {
		if p, ok := names[key]; ok {
			return p, true
		}
	}
	return Package{}, false
}

// Empty reports whether the index found no manifests at all.
func (ix *Index) Empty() bool { return len(ix.byDir) == 0 }

// normalizeName canonicalizes a package name for matching. PyPI is
// case-insensitive and treats '_' and '-' as equivalent (PEP 503).
func normalizeName(eco Ecosystem, name string) string {
	n := strings.TrimSpace(name)
	if eco == EcosystemPyPI {
		n = strings.ToLower(n)
		n = strings.ReplaceAll(n, "_", "-")
	}
	return n
}

// isAncestorDir reports whether dir is the same as or an ancestor of target.
func isAncestorDir(dir, target string) bool {
	dir = filepath.Clean(dir)
	target = filepath.Clean(target)
	if dir == target || dir == "." {
		return true
	}
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
