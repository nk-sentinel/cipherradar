package deps

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

// reqPinRE matches an exact requirements.txt pin: "name==1.2.3" (optionally with
// extras "name[extra]==1.2.3"). Only "==" counts as resolved.
var reqPinRE = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)`)

// parseRequirementsTxt parses requirements.txt. Only exact "==" pins are treated
// as resolved; ranges and unpinned entries are skipped.
func parseRequirementsTxt(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if m := reqPinRE.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, Package{
				Ecosystem: EcosystemPyPI, Name: m[1], Version: m[2],
				Direct: true, ManifestPath: path,
			})
		}
	}
	return pkgs, sc.Err()
}

// parsePipfileLock parses Pipfile.lock (JSON) — both the "default" and "develop"
// sections. Version strings look like "==1.2.3".
func parsePipfileLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var pkgs []Package
	for _, section := range []map[string]struct {
		Version string `json:"version"`
	}{lock.Default, lock.Develop} {
		for name, v := range section {
			pkgs = append(pkgs, Package{
				Ecosystem: EcosystemPyPI, Name: name,
				Version: strings.TrimPrefix(strings.TrimSpace(v.Version), "=="),
				Direct:  true, ManifestPath: path,
			})
		}
	}
	return pkgs, nil
}

var (
	poetryNameRE = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
	poetryVerRE  = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)
)

// parsePoetryLock parses poetry.lock by carving its [[package]] TOML blocks
// (name = "...", version = "..."). Hand-parsed to avoid a TOML dependency.
func parsePoetryLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	blocks := strings.Split(string(data), "[[package]]")
	for _, b := range blocks[1:] {
		// Stop at the next top-level table to avoid bleeding into other sections.
		if idx := strings.Index(b, "\n["); idx >= 0 {
			b = b[:idx]
		}
		nm := poetryNameRE.FindStringSubmatch(b)
		ver := poetryVerRE.FindStringSubmatch(b)
		if nm == nil {
			continue
		}
		p := Package{Ecosystem: EcosystemPyPI, Name: nm[1], Direct: true, ManifestPath: path}
		if ver != nil {
			p.Version = ver[1]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}
