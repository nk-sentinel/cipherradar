package configfile

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// opensslInstallRe matches apt-get/apt install of openssl without version pinning.
var opensslInstallRe = regexp.MustCompile(`(?i)(apt-get|apt)\s+install\s+.*\bopenssl\b`)

// opensslPinnedRe matches openssl with a version pin (openssl=version).
var opensslPinnedRe = regexp.MustCompile(`(?i)\bopenssl=[^\s]+`)

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

		// Detect unpinned openssl install.
		if strings.HasPrefix(strings.ToUpper(trimmed), "RUN") {
			if opensslInstallRe.MatchString(trimmed) && !opensslPinnedRe.MatchString(trimmed) {
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
		}

		// Detect EXPOSE 443 (TLS endpoint indicator).
		if strings.HasPrefix(strings.ToUpper(trimmed), "EXPOSE") {
			ports := strings.Fields(trimmed)
			for _, port := range ports[1:] {
				// Strip protocol suffix if present (e.g., "443/tcp").
				cleanPort := strings.Split(port, "/")[0]
				if cleanPort == "443" {
					findings = append(findings, makeFinding(
						types.AssetProtocol,
						"TLS endpoint: EXPOSE 443",
						path, lineNum, trimmed,
						types.SeverityInfo,
						"Dockerfile exposes port 443, indicating a TLS endpoint",
						"cbom-configfile-dockerfile-tls-port",
						types.CryptoProperties{ProtocolType: "tls"},
					))
					break
				}
			}
		}
	}

	return findings, nil
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
