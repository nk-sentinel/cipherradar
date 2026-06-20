package deps

import (
	"encoding/json"
	"os"
	"strings"
)

// parseNpmLock parses package-lock.json (lockfileVersion 1, 2, or 3) and returns
// resolved packages. v2/v3 use the "packages" map keyed by install path; v1 uses
// the recursive "dependencies" map.
func parseNpmLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var pkgs []Package
	seen := map[string]bool{}
	emit := func(name, version string, direct bool) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemNPM, Name: name, Version: version,
			Direct: direct, ManifestPath: path,
		})
	}

	// v2/v3: "packages" map. Keys: "" (root), "node_modules/<name>",
	// "node_modules/<a>/node_modules/<b>" (nested). Direct deps live directly
	// under the top-level node_modules (single segment after it).
	for key, v := range lock.Packages {
		if key == "" {
			continue
		}
		idx := strings.LastIndex(key, "node_modules/")
		if idx < 0 {
			continue
		}
		name := key[idx+len("node_modules/"):]
		if name == "" {
			continue
		}
		direct := strings.Count(key, "node_modules/") == 1
		emit(name, v.Version, direct)
	}

	// v1: recursive "dependencies".
	for name, v := range lock.Dependencies {
		emit(name, v.Version, true)
	}

	return pkgs, nil
}

// parsePackageJSON parses package.json for declared dependencies. Versions here
// are ranges, so they are treated as unresolved (empty Version) — the lockfile
// supplies the concrete version. Its value is marking direct dependencies.
func parsePackageJSON(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	var pkgs []Package
	for _, m := range []map[string]string{manifest.Dependencies, manifest.DevDependencies} {
		for name, spec := range m {
			pkgs = append(pkgs, Package{
				Ecosystem: EcosystemNPM, Name: name,
				Version: exactNpmVersion(spec), Direct: true, ManifestPath: path,
			})
		}
	}
	return pkgs, nil
}

// exactNpmVersion returns the version only when the spec is an exact pin (no
// range operators); otherwise "" so the lockfile resolution wins.
func exactNpmVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if strings.ContainsAny(spec, "^~><*|xX -") || strings.Contains(spec, "||") {
		return ""
	}
	return strings.TrimPrefix(spec, "=")
}
