// Package deps builds a project-wide dependency index from manifest and lockfile
// files (npm, Python, Maven/Gradle) and resolves a detected crypto library to a
// concrete package + version + purl. It is consulted by the library-enrichment
// pass; it is not a Scanner and emits no findings of its own.
package deps

import (
	"strings"
)

// Ecosystem identifies a package ecosystem.
type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemPyPI  Ecosystem = "pypi"
	EcosystemMaven Ecosystem = "maven"
)

// Package is a resolved dependency.
type Package struct {
	Ecosystem    Ecosystem
	Name         string // npm: "node-forge"; pypi: "cryptography"; maven: artifactId
	Group        string // Maven groupId; "" otherwise
	Version      string // resolved/locked version; "" if unresolved
	Direct       bool   // declared as a top-level dependency
	ManifestPath string // relative path of the manifest it came from
}

// BuildPurl renders a Package URL (purl) per the spec. Returns "" if there is
// not enough information (no name). A version-less purl is valid and returned
// when Version is empty.
func BuildPurl(p Package) string {
	if p.Name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(string(p.Ecosystem))
	b.WriteString("/")
	switch p.Ecosystem {
	case EcosystemMaven:
		if p.Group != "" {
			b.WriteString(encodePurlSegment(p.Group))
			b.WriteString("/")
		}
		b.WriteString(encodePurlSegment(p.Name))
	case EcosystemNPM:
		// Scoped packages: @scope/name -> %40scope/name
		if strings.HasPrefix(p.Name, "@") {
			parts := strings.SplitN(p.Name[1:], "/", 2)
			if len(parts) == 2 {
				b.WriteString("%40")
				b.WriteString(encodePurlSegment(parts[0]))
				b.WriteString("/")
				b.WriteString(encodePurlSegment(parts[1]))
				break
			}
		}
		b.WriteString(encodePurlSegment(p.Name))
	case EcosystemPyPI:
		// PyPI names are case-insensitive; canonicalize to lowercase.
		b.WriteString(encodePurlSegment(strings.ToLower(p.Name)))
	default:
		b.WriteString(encodePurlSegment(p.Name))
	}
	if p.Version != "" {
		b.WriteString("@")
		b.WriteString(encodePurlVersion(p.Version))
	}
	return b.String()
}

// encodePurlSegment percent-encodes characters that are not allowed unencoded in
// a purl namespace/name segment. The segment separator '/' and the chars
// '@' '?' '#' are encoded; common package-name characters are left as-is.
func encodePurlSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_' || r == '~':
			b.WriteRune(r)
		default:
			b.WriteString(percentEncode(r))
		}
	}
	return b.String()
}

// encodePurlVersion encodes a version segment. '+' (build metadata) and ':' are
// left as-is per common purl practice; '@' '/' '?' '#' are encoded.
func encodePurlVersion(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_' || r == '~' || r == '+' || r == ':':
			b.WriteRune(r)
		default:
			b.WriteString(percentEncode(r))
		}
	}
	return b.String()
}

func percentEncode(r rune) string {
	const hex = "0123456789ABCDEF"
	b := []byte(string(r))
	var out strings.Builder
	for _, c := range b {
		out.WriteByte('%')
		out.WriteByte(hex[c>>4])
		out.WriteByte(hex[c&0x0f])
	}
	return out.String()
}
