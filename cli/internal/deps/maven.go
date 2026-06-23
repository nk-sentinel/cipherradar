package deps

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// parsePomXML parses a Maven pom.xml <dependencies> block, resolving simple
// ${property} version references against the same pom's <properties> (best
// effort — no parent/reactor resolution).
func parsePomXML(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pom struct {
		Properties struct {
			Entries []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"properties"`
		Dependencies struct {
			Dependency []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
		DependencyManagement struct {
			Dependencies struct {
				Dependency []struct {
					GroupID    string `xml:"groupId"`
					ArtifactID string `xml:"artifactId"`
					Version    string `xml:"version"`
				} `xml:"dependency"`
			} `xml:"dependencies"`
		} `xml:"dependencyManagement"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}
	props := map[string]string{}
	for _, e := range pom.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	managed := map[string]string{}
	for _, d := range pom.DependencyManagement.Dependencies.Dependency {
		g := strings.TrimSpace(d.GroupID)
		a := strings.TrimSpace(d.ArtifactID)
		if g == "" || a == "" {
			continue
		}
		if v := resolvePomVersion(strings.TrimSpace(d.Version), props); v != "" {
			managed[g+":"+a] = v
		}
	}
	var pkgs []Package
	for _, d := range pom.Dependencies.Dependency {
		art := strings.TrimSpace(d.ArtifactID)
		if art == "" {
			continue
		}
		ver := resolvePomVersion(strings.TrimSpace(d.Version), props)
		if ver == "" {
			ver = managed[strings.TrimSpace(d.GroupID)+":"+art]
		}
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemMaven, Name: art, Group: strings.TrimSpace(d.GroupID),
			Version: ver, Direct: true, ManifestPath: path,
		})
	}
	return pkgs, nil
}

var pomPropRE = regexp.MustCompile(`^\$\{([^}]+)\}$`)

func resolvePomVersion(v string, props map[string]string) string {
	if m := pomPropRE.FindStringSubmatch(v); m != nil {
		if resolved, ok := props[m[1]]; ok {
			return resolved
		}
		return "" // unresolved property reference
	}
	if strings.ContainsAny(v, "[](),") { // version range
		return ""
	}
	return v
}

// gradleLockRE matches a gradle.lockfile line: "group:artifact:version=...".
var gradleLockRE = regexp.MustCompile(`^([\w.-]+):([\w.-]+):([\w.+-]+)=`)

// parseGradleLockfile parses gradle.lockfile lines of the form
// "group:artifact:version=configurations".
func parseGradleLockfile(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkgs []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := gradleLockRE.FindStringSubmatch(line); m != nil {
			pkgs = append(pkgs, Package{
				Ecosystem: EcosystemMaven, Group: m[1], Name: m[2], Version: m[3],
				ManifestPath: path,
			})
		}
	}
	return pkgs, sc.Err()
}

// gradleDepRE matches a pinned Gradle dependency string "group:artifact:version"
// inside implementation/api/etc. declarations (single or double quoted).
var gradleDepRE = regexp.MustCompile(`['"]([\w.-]+):([\w.-]+):([\w.+-]+)['"]`)

// parseBuildGradle parses build.gradle(.kts) for pinned "g:a:v" dependency
// strings. Versions containing Gradle interpolation ($var) are skipped.
//
// Inline pinned dependencies are processed before version-catalog (libs.*)
// aliases, and the per-(group:artifact) dedup means the first occurrence wins:
// an inline "g:a:v" string takes precedence over a catalog alias resolving to
// the same coordinate. A malformed or missing catalog is non-fatal — inline
// dependencies are still returned.
func parseBuildGradle(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	seen := map[string]bool{}
	emit := func(p Package) {
		key := p.Group + ":" + p.Name
		if p.Group == "" || p.Name == "" || seen[key] {
			return
		}
		seen[key] = true
		pkgs = append(pkgs, p)
	}
	for _, m := range gradleDepRE.FindAllStringSubmatch(string(data), -1) {
		if strings.Contains(m[3], "$") {
			continue
		}
		emit(Package{
			Ecosystem: EcosystemMaven, Group: m[1], Name: m[2], Version: m[3],
			Direct: true, ManifestPath: path,
		})
	}
	if catPath, ok := locateGradleCatalog(path); ok {
		if aliases, err := parseGradleVersionCatalog(catPath); err == nil && len(aliases) > 0 {
			for _, alias := range gradleCatalogAliasRE.FindAllStringSubmatch(string(data), -1) {
				if len(alias) < 2 {
					continue
				}
				if p, ok := aliases[normalizeCatalogAlias(alias[1])]; ok {
					p.Direct = true
					p.ManifestPath = path
					emit(p)
				}
			}
		}
	}
	return pkgs, nil
}

var gradleCatalogAliasRE = regexp.MustCompile(`\blibs\.([A-Za-z0-9_.-]+)\b`)
var gradleCatalogModuleRE = regexp.MustCompile(`module\s*=\s*"([^":]+):([^"]+)"`)
var gradleCatalogVersionRE = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
var gradleCatalogVersionRefRE = regexp.MustCompile(`version\.ref\s*=\s*"([^"]+)"`)
var gradleCatalogSimpleVersionRE = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"\s*$`)

func locateGradleCatalog(buildGradlePath string) (string, bool) {
	start := filepath.Dir(buildGradlePath)
	for {
		p := filepath.Join(start, "gradle", "libs.versions.toml")
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
		parent := filepath.Dir(start)
		if parent == start {
			return "", false
		}
		start = parent
	}
}

func normalizeCatalogAlias(alias string) string {
	alias = strings.TrimSpace(alias)
	alias = strings.ReplaceAll(alias, "-", ".")
	alias = strings.ReplaceAll(alias, "_", ".")
	return alias
}

func parseGradleVersionCatalog(path string) (map[string]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	versions := map[string]string{}
	libs := map[string]Package{}
	section := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		switch section {
		case "versions":
			if m := gradleCatalogSimpleVersionRE.FindStringSubmatch(line); m != nil {
				versions[normalizeCatalogAlias(m[1])] = strings.TrimSpace(m[2])
			}
		case "libraries":
			eq := strings.Index(line, "=")
			if eq <= 0 {
				continue
			}
			alias := normalizeCatalogAlias(strings.TrimSpace(line[:eq]))
			body := strings.TrimSpace(line[eq+1:])
			mod := gradleCatalogModuleRE.FindStringSubmatch(body)
			if len(mod) != 3 {
				continue
			}
			p := Package{Ecosystem: EcosystemMaven, Group: strings.TrimSpace(mod[1]), Name: strings.TrimSpace(mod[2])}
			if v := gradleCatalogVersionRE.FindStringSubmatch(body); len(v) == 2 {
				p.Version = strings.TrimSpace(v[1])
			} else if vr := gradleCatalogVersionRefRE.FindStringSubmatch(body); len(vr) == 2 {
				p.Version = versions[normalizeCatalogAlias(vr[1])]
			}
			libs[alias] = p
		}
	}
	return libs, nil
}
