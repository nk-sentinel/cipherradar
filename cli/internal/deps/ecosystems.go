package deps

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// --- Rust: Cargo.lock ---------------------------------------------------------

var (
	cargoNameRE = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
	cargoVerRE  = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)
)

// parseCargoLock parses Cargo.lock [[package]] TOML blocks (name + version).
func parseCargoLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	for _, b := range strings.Split(string(data), "[[package]]")[1:] {
		if idx := strings.Index(b, "\n["); idx >= 0 {
			b = b[:idx]
		}
		nm := cargoNameRE.FindStringSubmatch(b)
		if nm == nil {
			continue
		}
		p := Package{Ecosystem: EcosystemCargo, Name: nm[1], Direct: true, ManifestPath: path}
		if ver := cargoVerRE.FindStringSubmatch(b); ver != nil {
			p.Version = ver[1]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// --- Ruby: Gemfile.lock -------------------------------------------------------

// gemSpecRE matches a Gemfile.lock spec line: "    name (1.2.3)".
var gemSpecRE = regexp.MustCompile(`^\s{4,6}([A-Za-z0-9._-]+) \(([0-9][^)]*)\)\s*$`)

// parseGemfileLock parses the GEM specs section of a Gemfile.lock. Only the
// resolved top-level spec lines (4–6 space indent) are taken; deeper-indented
// transitive constraint lines are ignored.
func parseGemfileLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkgs []Package
	inSpecs := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		// A non-indented line ends the GEM section.
		if line != "" && line[0] != ' ' {
			inSpecs = false
		}
		if !inSpecs {
			continue
		}
		if m := gemSpecRE.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, Package{
				Ecosystem: EcosystemGem, Name: m[1], Version: m[2],
				Direct: true, ManifestPath: path,
			})
		}
	}
	return pkgs, sc.Err()
}

// --- Go: go.mod ---------------------------------------------------------------

// goRequireRE matches a require line "module vX.Y.Z" (inside or outside a block).
var goRequireRE = regexp.MustCompile(`^\s*(?:require\s+)?([\w./~-]+\.[\w./~-]+)\s+(v[0-9][\w.+-]*)`)

// parseGoMod parses go.mod require directives into module + version.
func parseGoMod(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkgs []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "module ") || strings.HasPrefix(trimmed, "go ") {
			continue
		}
		if m := goRequireRE.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, Package{
				Ecosystem: EcosystemGolang, Name: m[1], Version: m[2],
				Direct:       !strings.Contains(line, "// indirect"),
				ManifestPath: path,
			})
		}
	}
	return pkgs, sc.Err()
}
