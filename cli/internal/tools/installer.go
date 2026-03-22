// Package tools provides installation and management of external analysis
// tools used by the CipherRadar CLI (e.g. OpenGrep).
package tools

import (
	"archive/tar"
	"archive/zip"
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
	OpenGrepVersion = "v1.16.5"

	// OpenGrepBaseURL is the GitHub Releases base URL for OpenGrep.
	OpenGrepBaseURL = "https://github.com/opengrep/opengrep/releases/download"

	// YARAXVersion is the pinned YARA-X release to install.
	YARAXVersion = "v0.12.0"

	// YARAXBaseURL is the GitHub Releases base URL for YARA-X.
	YARAXBaseURL = "https://github.com/VirusTotal/yara-x/releases/download"
)

// DefaultToolsDir returns the default directory where cradar installs tools
// (~/.cradar/tools).
func DefaultToolsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cradar", "tools")
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

	// Map Go platform names to OpenGrep release naming convention.
	osName := goos
	if osName == "darwin" {
		osName = "osx"
	}
	arch := goarch
	if arch == "amd64" {
		arch = "x86_64"
	}
	if arch == "arm64" {
		arch = "aarch64"
	}

	filename := fmt.Sprintf("opengrep-core_%s_%s.tar.gz", osName, arch)
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

	if err := extractBinaryFromTarGz(tmpPath, destPath, "opengrep-core"); err != nil {
		return fmt.Errorf("extracting OpenGrep: %w", err)
	}

	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("setting executable permission: %w", err)
	}

	fmt.Printf("OpenGrep %s installed to %s\n", OpenGrepVersion, destPath)
	return nil
}

// Joern (Pass 3) was removed in ADR-033. All Joern query patterns are now
// covered by OpenGrep taint rules (Pass 2) with 19x better performance.

// IsYARAXInstalled returns true if a yr binary exists in toolsDir.
func IsYARAXInstalled(toolsDir string) bool {
	path := filepath.Join(toolsDir, "yr")
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// InstallYARAX downloads the YARA-X binary to the specified directory.
func InstallYARAX(toolsDir string) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	arch := goarch
	if arch == "amd64" {
		arch = "x86_64"
	}
	if arch == "arm64" {
		arch = "aarch64"
	}

	var target string
	switch goos {
	case "darwin":
		target = arch + "-apple-darwin"
	case "linux":
		target = arch + "-unknown-linux-gnu"
	case "windows":
		target = arch + "-pc-windows-msvc"
	default:
		return fmt.Errorf("unsupported OS: %s", goos)
	}

	filename := fmt.Sprintf("yr-%s-%s.tar.gz", YARAXVersion, target)
	url := fmt.Sprintf("%s/%s/%s", YARAXBaseURL, YARAXVersion, filename)

	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("creating tools directory: %w", err)
	}

	destPath := filepath.Join(toolsDir, "yr")

	fmt.Printf("Downloading YARA-X %s for %s/%s...\n", YARAXVersion, goos, arch)
	fmt.Printf("URL: %s\n", url)

	resp, err := http.Get(url) //nolint:gosec // URL is constructed from constants, not user input
	if err != nil {
		return fmt.Errorf("downloading YARA-X: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d -- check if YARA-X %s is available for %s",
			resp.StatusCode, YARAXVersion, target)
	}

	tmpFile, err := os.CreateTemp(toolsDir, "yarax-download-*")
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

	if err := extractBinaryFromTarGz(tmpPath, destPath, "yr"); err != nil {
		return fmt.Errorf("extracting YARA-X: %w", err)
	}

	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("setting executable permission: %w", err)
	}

	fmt.Printf("YARA-X %s installed to %s\n", YARAXVersion, destPath)
	return nil
}

// extractZip extracts all files from a zip archive to destDir.
func extractZip(archivePath, destDir string) error {
	r, err := zipOpen(archivePath)
	if err != nil {
		return fmt.Errorf("opening zip archive: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		destPath := filepath.Join(destDir, f.Name) //nolint:gosec // paths are from trusted archive

		// Ensure the path is within destDir (zip slip protection).
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in archive: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("creating parent directory: %w", err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening file in archive: %w", err)
		}

		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("creating output file: %w", err)
		}

		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return fmt.Errorf("writing file: %w", err)
		}

		out.Close()
		rc.Close()
	}

	return nil
}

// zipOpen is a wrapper around zip.OpenReader for testability.
var zipOpen = zipOpenReader

func zipOpenReader(path string) (*zip.ReadCloser, error) {
	return zip.OpenReader(path)
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
