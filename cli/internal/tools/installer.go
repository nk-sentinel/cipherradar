// Package tools provides installation and management of external analysis
// tools used by the CipherRadar CLI (e.g. OpenGrep).
package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
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
	YARAXVersion = "v1.14.0"

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

// openGrepAsset returns the asset name for the current platform. The
// standalone single-file binary is preferred -- no tarball extraction.
func openGrepAsset() (assetName string, err error) {
	switch {
	case goos() == "linux" && goarch() == "amd64":
		// Opengrep names the linux/amd64 asset "x86" (project convention,
		// even though the binary is 64-bit). The earlier amd64->x86_64
		// rewrite produced a 404.
		return "opengrep_manylinux_x86", nil
	case goos() == "linux" && goarch() == "arm64":
		return "opengrep_manylinux_aarch64", nil
	case goos() == "darwin" && goarch() == "amd64":
		return "opengrep_osx_x86", nil
	case goos() == "darwin" && goarch() == "arm64":
		// Note: opengrep uses "arm64" here, not "aarch64" (different from linux).
		return "opengrep_osx_arm64", nil
	default:
		return "", fmt.Errorf("unsupported platform: %s/%s", goos(), goarch())
	}
}

// openGrepReleaseAPI is the GitHub Releases API endpoint for the pinned
// OpenGrep version. Exposed as a var so tests can swap it for an httptest
// server URL.
var openGrepReleaseAPI = fmt.Sprintf(
	"https://api.github.com/repos/opengrep/opengrep/releases/tags/%s",
	OpenGrepVersion,
)

// yaraXReleaseAPI is the GitHub Releases API endpoint for the pinned
// YARA-X version. Exposed as a var so tests can swap it for an httptest
// server URL — mirrors the openGrepReleaseAPI pattern.
var yaraXReleaseAPI = fmt.Sprintf(
	"https://api.github.com/repos/VirusTotal/yara-x/releases/tags/%s",
	YARAXVersion,
)

// githubReleaseAsset is the subset of the GitHub Releases API asset shape we
// care about. The `digest` field is GitHub-computed (format "sha256:<hex>")
// and exists on every release asset.
type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

type githubReleaseResponse struct {
	Assets []githubReleaseAsset `json:"assets"`
}

// fetchReleaseAsset GETs the release metadata from the GitHub API and returns
// (downloadURL, sha256-hex-digest) for the named asset. Returns an error if
// the asset is missing from the release or its digest field is empty / not
// sha256-prefixed.
func fetchReleaseAsset(apiURL, assetName string) (downloadURL, sha256Hex string, err error) {
	if err := requireHTTPS(apiURL); err != nil {
		return "", "", err
	}
	resp, err := http.Get(apiURL) //nolint:gosec // URL constructed from package constants
	if err != nil {
		return "", "", fmt.Errorf("GET %s: %w", apiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("release API %s: HTTP %d", apiURL, resp.StatusCode)
	}
	var release githubReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("decode release JSON: %w", err)
	}
	for _, a := range release.Assets {
		if a.Name == assetName {
			if !strings.HasPrefix(a.Digest, "sha256:") {
				return "", "", fmt.Errorf("asset %s has unexpected digest format %q (want sha256:<hex>)", assetName, a.Digest)
			}
			return a.BrowserDownloadURL, strings.TrimPrefix(a.Digest, "sha256:"), nil
		}
	}
	return "", "", fmt.Errorf("asset %q not found in release %s", assetName, apiURL)
}

// InstallOpenGrep downloads the OpenGrep binary to toolsDir and verifies
// its SHA-256 against the digest reported by the GitHub Releases API.
func InstallOpenGrep(toolsDir string) error {
	assetName, err := openGrepAsset()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("creating tools directory: %w", err)
	}
	destPath := filepath.Join(toolsDir, "opengrep")

	fmt.Printf("Downloading OpenGrep %s for %s/%s...\n", OpenGrepVersion, goos(), goarch())

	binURL, expectedSum, err := fetchReleaseAsset(openGrepReleaseAPI, assetName)
	if err != nil {
		return fmt.Errorf("fetching release metadata: %w", err)
	}
	fmt.Printf("URL: %s\n", binURL)

	tmpPath, err := downloadToTemp(binURL, toolsDir, "opengrep-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := VerifySHA256(tmpPath, expectedSum); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("setting executable permission: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("moving binary into place: %w", err)
	}

	fmt.Printf("OpenGrep %s installed to %s (sha256 verified via GitHub API)\n", OpenGrepVersion, destPath)
	return nil
}

// downloadToTemp streams binURL into a temp file in dir and returns its path.
// The caller is responsible for removing the file. Only HTTPS URLs are accepted.
func downloadToTemp(binURL, dir, pattern string) (string, error) {
	if err := requireHTTPS(binURL); err != nil {
		return "", err
	}
	resp, err := http.Get(binURL) //nolint:gosec // URL is provided by the trusted release API response
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", binURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", binURL, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("saving download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	return tmpPath, nil
}

// requireHTTPS rejects non-HTTPS schemes so installer downloads cannot be
// downgraded to plaintext.
func requireHTTPS(url string) error {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("refusing non-HTTPS URL: %s", url)
	}
	return nil
}

// platform getters for testability.
func goos() string   { return runtime.GOOS }
func goarch() string { return runtime.GOARCH }

// Joern (Pass 3) was removed in ADR-033. All Joern query patterns are now
// covered by OpenGrep taint rules (Pass 2) with 19x better performance.

// IsYARAXInstalled returns true if a yr binary exists in toolsDir.
func IsYARAXInstalled(toolsDir string) bool {
	path := filepath.Join(toolsDir, "yr")
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// yaraXAsset returns the YARA-X release asset filename for the current
// host platform. Mirrors openGrepAsset; centralising the per-OS naming
// keeps the SHA-256 verification path symmetric for both tools.
func yaraXAsset() (string, error) {
	arch := goarch()
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	}

	var target string
	switch goos() {
	case "darwin":
		target = arch + "-apple-darwin"
	case "linux":
		target = arch + "-unknown-linux-gnu"
	case "windows":
		target = arch + "-pc-windows-msvc"
	default:
		return "", fmt.Errorf("unsupported OS for YARA-X: %s", goos())
	}

	// YARA-X archives: gzipped tar on unix, zip on windows.
	ext := "gz"
	if goos() == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("yara-x-%s-%s.%s", YARAXVersion, target, ext), nil
}

// InstallYARAX downloads the YARA-X binary to toolsDir and verifies
// its SHA-256 against the digest reported by the GitHub Releases API
// — same pattern InstallOpenGrep follows.
//
// Closes the ADR-038 gap: the previous implementation streamed the
// archive over HTTPS without checksum verification, which left the
// install path vulnerable to a TLS-terminating proxy or GitHub CDN
// edge serving altered bytes. The release API returns a GitHub-computed
// `digest` field on every asset, so we get the canonical sha256 for
// free without maintaining a separate pin list.
func InstallYARAX(toolsDir string) error {
	assetName, err := yaraXAsset()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return fmt.Errorf("creating tools directory: %w", err)
	}

	destPath := filepath.Join(toolsDir, "yr")
	if goos() == "windows" {
		destPath += ".exe"
	}

	fmt.Printf("Downloading YARA-X %s for %s/%s...\n", YARAXVersion, goos(), goarch())

	binURL, expectedSum, err := fetchReleaseAsset(yaraXReleaseAPI, assetName)
	if err != nil {
		return fmt.Errorf("fetching YARA-X release metadata: %w", err)
	}
	fmt.Printf("URL: %s\n", binURL)

	tmpPath, err := downloadToTemp(binURL, toolsDir, "yarax-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := VerifySHA256(tmpPath, expectedSum); err != nil {
		return err
	}

	// Extract the actual yr binary out of the verified archive. For
	// unix the archive is a gzipped tar containing a single `yr`
	// binary; for windows it's a zip containing `yr.exe`.
	if goos() == "windows" {
		extractDir, err := os.MkdirTemp(toolsDir, "yarax-extract-*")
		if err != nil {
			return fmt.Errorf("creating extract dir: %w", err)
		}
		defer os.RemoveAll(extractDir)
		if err := extractZip(tmpPath, extractDir); err != nil {
			return fmt.Errorf("extracting YARA-X zip: %w", err)
		}
		yrExe := filepath.Join(extractDir, "yr.exe")
		if err := os.Rename(yrExe, destPath); err != nil {
			return fmt.Errorf("moving yr.exe: %w", err)
		}
	} else {
		if err := extractBinaryFromTarGz(tmpPath, destPath, "yr"); err != nil {
			return fmt.Errorf("extracting YARA-X: %w", err)
		}
	}

	if err := os.Chmod(destPath, 0o755); err != nil {
		return fmt.Errorf("setting executable permission: %w", err)
	}

	fmt.Printf("YARA-X %s installed to %s (sha256 verified via GitHub API)\n", YARAXVersion, destPath)
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
