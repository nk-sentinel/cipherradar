// Package tools provides installation and management of external analysis
// tools used by the CipherRadar CLI (e.g. OpenGrep).
package tools

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// OpenGrepVersion is the pinned OpenGrep release to install.
	OpenGrepVersion = "v1.102.0"

	// OpenGrepBaseURL is the GitHub Releases base URL for OpenGrep.
	OpenGrepBaseURL = "https://github.com/opengrep/opengrep/releases/download"
)

// DefaultToolsDir returns the default directory where cbom installs tools
// (~/.cbom/tools).
func DefaultToolsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cbom", "tools")
}

// IsOpenGrepInstalled returns true if an opengrep binary exists in toolsDir.
func IsOpenGrepInstalled(toolsDir string) bool {
	path := filepath.Join(toolsDir, "opengrep")
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// InstallOpenGrep downloads the OpenGrep binary to the specified directory.
func InstallOpenGrep(toolsDir string) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	arch := goarch
	if arch == "amd64" {
		arch = "x86_64"
	}

	filename := fmt.Sprintf("opengrep-%s-%s-%s.tar.gz", OpenGrepVersion, goos, arch)
	url := fmt.Sprintf("%s/%s/%s", OpenGrepBaseURL, OpenGrepVersion, filename)

	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("creating tools directory: %w", err)
	}

	destPath := filepath.Join(toolsDir, "opengrep")

	fmt.Printf("Downloading OpenGrep %s for %s/%s...\n", OpenGrepVersion, goos, arch)
	fmt.Printf("URL: %s\n", url)

	resp, err := http.Get(url) //nolint:gosec // URL is constructed from constants, not user input
	if err != nil {
		return fmt.Errorf("downloading OpenGrep: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d -- check if OpenGrep %s is available for %s/%s",
			resp.StatusCode, OpenGrepVersion, goos, arch)
	}

	tmpFile, err := os.CreateTemp(toolsDir, "opengrep-download-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("saving download: %w", err)
	}
	tmpFile.Close()

	if err := extractBinaryFromTarGz(tmpPath, destPath, "opengrep"); err != nil {
		return fmt.Errorf("extracting OpenGrep: %w", err)
	}

	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("setting executable permission: %w", err)
	}

	fmt.Printf("OpenGrep %s installed to %s\n", OpenGrepVersion, destPath)
	return nil
}

// extractBinaryFromTarGz extracts a single file whose base name matches
// targetName from the gzipped tar archive at archivePath and writes it to
// destPath. It returns an error if the target file is not found.
func extractBinaryFromTarGz(archivePath, destPath, targetName string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		base := filepath.Base(hdr.Name)
		if hdr.Typeflag == tar.TypeReg && (base == targetName || strings.HasPrefix(base, targetName)) {
			out, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("writing binary: %w", err)
			}
			out.Close()
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in archive", targetName)
}

// PlatformArchive returns the expected archive filename for the current platform.
// Exported for testing.
func PlatformArchive() string {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	return fmt.Sprintf("opengrep-%s-%s-%s.tar.gz", OpenGrepVersion, runtime.GOOS, arch)
}
