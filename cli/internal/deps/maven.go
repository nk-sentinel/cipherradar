package deps

import (
	"bufio"
	"encoding/xml"
	"os"
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
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}
	props := map[string]string{}
	for _, e := range pom.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	var pkgs []Package
	for _, d := range pom.Dependencies.Dependency {
		art := strings.TrimSpace(d.ArtifactID)
		if art == "" {
			continue
		}
		ver := resolvePomVersion(strings.TrimSpace(d.Version), props)
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
func parseBuildGradle(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	for _, m := range gradleDepRE.FindAllStringSubmatch(string(data), -1) {
		if strings.Contains(m[3], "$") {
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemMaven, Group: m[1], Name: m[2], Version: m[3],
			Direct: true, ManifestPath: path,
		})
	}
	return pkgs, nil
}
