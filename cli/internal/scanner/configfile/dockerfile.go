package configfile

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// pkgInstallRe matches a package-manager install command across the common
// Linux distros: Debian/Ubuntu (apt/apt-get), Alpine (apk add), and
// RHEL/Fedora (yum/dnf install). Flags such as --no-cache or -y between the
// verb and the package list are tolerated.
var pkgInstallRe = regexp.MustCompile(`(?i)\b(?:apt-get|apt|yum|dnf|microdnf|apk)\s+(?:install|add)\b`)

// opensslPkgRe matches the openssl runtime package name as a whole word.
var opensslPkgRe = regexp.MustCompile(`(?i)\bopenssl\b`)

// opensslPinnedRe matches openssl with a version pin (openssl=version or
// openssl-3.0.2 for apk/yum style pins).
var opensslPinnedRe = regexp.MustCompile(`(?i)\bopenssl[=-][0-9][^\s]*`)

// cryptoLibPkgRe matches common OpenSSL development / shared library packages
// across distros: libssl-dev, libssl1.1, openssl-dev, openssl-libs. Kept tight
// to these exact package names so arbitrary packages are never matched.
var cryptoLibPkgRe = regexp.MustCompile(`(?i)\b(?:libssl-dev|libssl[0-9][0-9.]*|openssl-dev|openssl-libs)\b`)

// tlsPorts is the set of EXPOSE ports treated as TLS/HTTPS endpoints.
var tlsPorts = map[string]bool{"443": true, "8443": true}

// DockerfileScanner detects crypto-related patterns in Dockerfiles.
type DockerfileScanner struct{}

// NewDockerfile creates a new DockerfileScanner.
func NewDockerfile() *DockerfileScanner {
	return &DockerfileScanner{}
}

// Name returns the scanner name.
func (s *DockerfileScanner) Name() string { return "dockerfile" }

// Extensions returns the file extensions this scanner handles.
// Dockerfiles typically have no extension, so we match by filename instead.
// The scanner is registered as a universal scanner that checks filenames.
func (s *DockerfileScanner) Extensions() []string { return nil }

// ScanFile scans a Dockerfile for crypto-related patterns.
func (s *DockerfileScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	// Only process files that look like Dockerfiles.
	if !isDockerfile(path, content) {
		return nil, nil
	}

	var findings []types.Finding
	lines := bytes.Split(content, []byte("\n"))

	for i, line := range lines {
		lineStr := string(line)
		trimmed := strings.TrimSpace(lineStr)
		lineNum := i + 1

		// Skip comments and empty lines.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect unpinned crypto-package installs (openssl runtime + dev/shared
		// libraries) across apt/apt-get/apk/yum/dnf.
		if strings.HasPrefix(strings.ToUpper(trimmed), "RUN") && pkgInstallRe.MatchString(trimmed) {
			// openssl runtime package (skip when version-pinned).
			if opensslPkgRe.MatchString(trimmed) && !opensslPinnedRe.MatchString(trimmed) {
				findings = append(findings, makeFinding(
					types.AssetAlgorithm,
					"Unpinned OpenSSL install",
					path, lineNum, trimmed,
					types.SeverityMedium,
					"Dockerfile installs openssl without version pinning",
					"cbom-configfile-dockerfile-unpinned-openssl",
					types.CryptoProperties{AlgorithmFamily: "openssl"},
				))
			}
			// OpenSSL dev/shared library packages (libssl-dev, openssl-libs, ...).
			if cryptoLibPkgRe.MatchString(trimmed) {
				findings = append(findings, makeFinding(
					types.AssetAlgorithm,
					"Unpinned crypto library install",
					path, lineNum, trimmed,
					types.SeverityMedium,
					"Dockerfile installs an OpenSSL development/shared library package",
					"cbom-configfile-dockerfile-unpinned-crypto-lib",
					types.CryptoProperties{AlgorithmFamily: "openssl"},
				))
			}
		}

		// Detect EXPOSE of a TLS/HTTPS port (443, 8443).
		if strings.HasPrefix(strings.ToUpper(trimmed), "EXPOSE") {
			ports := strings.Fields(trimmed)
			for _, port := range ports[1:] {
				// Strip protocol suffix if present (e.g., "443/tcp").
				cleanPort := strings.Split(port, "/")[0]
				if tlsPorts[cleanPort] {
					findings = append(findings, makeFinding(
						types.AssetProtocol,
						"TLS endpoint: EXPOSE "+cleanPort,
						path, lineNum, trimmed,
						types.SeverityInfo,
						"Dockerfile exposes port "+cleanPort+", indicating a TLS endpoint",
						"cbom-configfile-dockerfile-tls-port",
						types.CryptoProperties{ProtocolType: "tls"},
					))
				}
			}
		}
	}

	return scanner.AnnotateFindings(findings), nil
}

// isDockerfile heuristically determines if a file is a Dockerfile.
// Only filename-based detection is used. Content-based detection is
// intentionally omitted to avoid false positives on arbitrary files
// that happen to contain "FROM" (e.g., shell scripts, Go files).
func isDockerfile(path string, _ []byte) bool {
	pathLower := strings.ToLower(path)
	parts := strings.Split(pathLower, "/")
	basename := parts[len(parts)-1]

	return basename == "dockerfile" || strings.HasPrefix(basename, "dockerfile.") ||
		strings.HasSuffix(basename, ".dockerfile")
}
