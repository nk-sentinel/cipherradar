package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// helperAPIServer serves a GitHub-API-shaped release response at /api and the
// matching binary at /assets/bin. Digest is computed from body.
func helperAPIServer(t *testing.T, body []byte, assetName string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256(body)
		resp := map[string]any{
			"assets": []map[string]any{
				{
					"name":                 assetName,
					"browser_download_url": srvURL + "/assets/bin",
					"digest":               "sha256:" + hex.EncodeToString(sum[:]),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/assets/bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})
	srv := httptest.NewTLSServer(mux)
	srvURL = srv.URL
	return srv
}

func TestFetchReleaseAsset_ParsesDigest(t *testing.T) {
	srv := helperAPIServer(t, []byte("payload"), "opengrep_manylinux_x86")
	defer srv.Close()
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	url, digest, err := fetchReleaseAsset(srv.URL+"/api", "opengrep_manylinux_x86")
	if err != nil {
		t.Fatalf("fetchReleaseAsset: %v", err)
	}
	want := sha256.Sum256([]byte("payload"))
	if digest != hex.EncodeToString(want[:]) {
		t.Errorf("digest = %q want %q", digest, hex.EncodeToString(want[:]))
	}
	if !strings.HasSuffix(url, "/assets/bin") {
		t.Errorf("download URL = %q, want suffix /assets/bin", url)
	}
}

func TestFetchReleaseAsset_RejectsNonHTTPS(t *testing.T) {
	_, _, err := fetchReleaseAsset("http://example.com/api", "x")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("expected non-HTTPS rejection, got %v", err)
	}
}

func TestFetchReleaseAsset_MissingAssetIsError(t *testing.T) {
	srv := helperAPIServer(t, []byte("p"), "actually-present")
	defer srv.Close()
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	_, _, err := fetchReleaseAsset(srv.URL+"/api", "not-in-release")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got %v", err)
	}
}

func TestFetchReleaseAsset_MalformedDigestRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"assets": []map[string]any{
				{"name": "x", "browser_download_url": "https://example/x", "digest": "md5:abcd"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	_, _, err := fetchReleaseAsset(srv.URL+"/api", "x")
	if err == nil || !strings.Contains(err.Error(), "unexpected digest format") {
		t.Errorf("expected digest format rejection, got %v", err)
	}
}

func TestDownloadToTemp_StreamsAndPlacesFile(t *testing.T) {
	srv := helperAPIServer(t, []byte("payload"), "x")
	defer srv.Close()
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	dir := t.TempDir()
	path, err := downloadToTemp(srv.URL+"/assets/bin", dir, "test-*")
	if err != nil {
		t.Fatalf("downloadToTemp: %v", err)
	}
	defer os.Remove(path)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("body = %q want %q", got, "payload")
	}
	if filepath.Dir(path) != dir {
		t.Errorf("temp file should be inside %q, got %q", dir, path)
	}
}

func TestInstaller_ChecksumMismatchRejected(t *testing.T) {
	// API advertises digest of "different" but serves "payload".
	body := []byte("payload")
	wrongSum := sha256.Sum256([]byte("different"))
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"assets": []map[string]any{
				{
					"name":                 "x",
					"browser_download_url": srvURL + "/assets/bin",
					"digest":               "sha256:" + hex.EncodeToString(wrongSum[:]),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/assets/bin", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	url, digest, err := fetchReleaseAsset(srv.URL+"/api", "x")
	if err != nil {
		t.Fatalf("fetchReleaseAsset: %v", err)
	}
	tmp := t.TempDir()
	path, err := downloadToTemp(url, tmp, "test-*")
	if err != nil {
		t.Fatalf("downloadToTemp: %v", err)
	}
	defer os.Remove(path)

	if err := VerifySHA256(path, digest); err == nil {
		t.Fatal("expected checksum mismatch, got nil")
	}
}

func TestOpenGrepAsset_PlatformNaming(t *testing.T) {
	// Check the platform mapping for the current host.
	asset, err := openGrepAsset()
	if err != nil {
		t.Skip("unsupported platform for asset mapping")
	}
	switch {
	case goos() == "linux" && goarch() == "amd64":
		if asset != "opengrep_manylinux_x86" {
			t.Errorf("linux/amd64 asset = %q, want opengrep_manylinux_x86", asset)
		}
	case goos() == "darwin" && goarch() == "arm64":
		if asset != "opengrep_osx_arm64" {
			t.Errorf("darwin/arm64 asset = %q, want opengrep_osx_arm64 (NOT aarch64)", asset)
		}
	}
}

func TestDefaultToolsDirEndsWithCradarTools(t *testing.T) {
	dir := DefaultToolsDir()
	if !strings.HasSuffix(dir, filepath.Join(".cradar", "tools")) {
		t.Errorf("expected DefaultToolsDir to end with .cradar/tools, got %s", dir)
	}
}

func TestIsOpenGrepInstalledReturnsFalseForEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	if IsOpenGrepInstalled(tmpDir) {
		t.Error("expected IsOpenGrepInstalled to return false for empty directory")
	}
}

func TestIsOpenGrepInstalledReturnsTrueWhenFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	ogPath := filepath.Join(tmpDir, "opengrep")
	if err := os.WriteFile(ogPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if !IsOpenGrepInstalled(tmpDir) {
		t.Error("expected IsOpenGrepInstalled to return true when file exists")
	}
}

func TestIsOpenGrepInstalledReturnsFalseForDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dirPath := filepath.Join(tmpDir, "opengrep")
	if err := os.Mkdir(dirPath, 0755); err != nil {
		t.Fatal(err)
	}
	if IsOpenGrepInstalled(tmpDir) {
		t.Error("expected IsOpenGrepInstalled to return false when path is a directory")
	}
}

func TestExtractBinaryFromTarGz(t *testing.T) {
	// Build a tar.gz in memory containing a dummy "opengrep" file.
	content := []byte("fake-opengrep-binary-content")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "opengrep",
		Mode: 0755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	// Write the archive to a temp file.
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(tmpDir, "opengrep")
	if err := extractBinaryFromTarGz(archivePath, destPath, "opengrep"); err != nil {
		t.Fatalf("extractBinaryFromTarGz failed: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("extracted content mismatch: got %q, want %q", got, content)
	}
}

func TestExtractBinaryFromTarGzNestedPath(t *testing.T) {
	// Binary inside a subdirectory within the archive.
	content := []byte("nested-opengrep-binary")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "opengrep-v1.102.0/bin/opengrep",
		Mode: 0755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "nested.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(tmpDir, "opengrep")
	if err := extractBinaryFromTarGz(archivePath, destPath, "opengrep"); err != nil {
		t.Fatalf("extractBinaryFromTarGz with nested path failed: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("extracted content mismatch: got %q, want %q", got, content)
	}
}

func TestExtractBinaryFromTarGzNotFound(t *testing.T) {
	// Archive with no matching file.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "some-other-binary",
		Mode: 0755,
		Size: 5,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "nogrep.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(tmpDir, "opengrep")
	err := extractBinaryFromTarGz(archivePath, destPath, "opengrep")
	if err == nil {
		t.Fatal("expected error when binary not found in archive")
	}
	if !strings.Contains(err.Error(), "not found in archive") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPlatformArchiveReturnsValidCombination(t *testing.T) {
	archive := PlatformArchive()

	if !strings.HasPrefix(archive, "opengrep-"+OpenGrepVersion+"-") {
		t.Errorf("archive should start with opengrep-<version>-, got %s", archive)
	}
	if !strings.HasSuffix(archive, ".tar.gz") {
		t.Errorf("archive should end with .tar.gz, got %s", archive)
	}

	// Verify the archive contains the current GOOS.
	if !strings.Contains(archive, runtime.GOOS) {
		t.Errorf("archive should contain GOOS %s, got %s", runtime.GOOS, archive)
	}

	// Verify arch mapping: amd64 should map to x86_64.
	if runtime.GOARCH == "amd64" {
		if !strings.Contains(archive, "x86_64") {
			t.Errorf("archive should contain x86_64 for amd64, got %s", archive)
		}
	} else {
		if !strings.Contains(archive, runtime.GOARCH) {
			t.Errorf("archive should contain GOARCH %s, got %s", runtime.GOARCH, archive)
		}
	}
}

// helperYARAXServer serves a GitHub-API-shaped release response at /api
// and the matching gzipped tar at /assets/bin. Tar carries a `yr`
// binary holding the supplied yrBody bytes; digest is computed over
// the tar archive. Returns the test server.
func helperYARAXServer(t *testing.T, yrBody []byte) (*httptest.Server, []byte) {
	t.Helper()

	// Build a gzipped tar containing a single "yr" entry — mirrors
	// the upstream YARA-X release artifact layout.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{Name: "yr", Mode: 0o755, Size: int64(len(yrBody))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(yrBody); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)

	mux := http.NewServeMux()
	var srvURL string

	asset, err := yaraXAsset()
	if err != nil {
		t.Skipf("YARA-X asset name unavailable on this platform: %v", err)
	}

	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"assets": []map[string]any{
				{
					"name":                 asset,
					"browser_download_url": srvURL + "/assets/bin",
					"digest":               "sha256:" + hex.EncodeToString(sum[:]),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/assets/bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	})

	srv := httptest.NewTLSServer(mux)
	srvURL = srv.URL
	return srv, archive
}

func TestInstallYARAX_VerifiesSHA256(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("InstallYARAX windows path uses zip, not tar.gz — covered by separate fixture if needed")
	}

	yrBody := []byte("fake-yr-binary-content")
	srv, _ := helperYARAXServer(t, yrBody)
	defer srv.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	origAPI := yaraXReleaseAPI
	yaraXReleaseAPI = srv.URL + "/api"
	defer func() { yaraXReleaseAPI = origAPI }()

	tmp := t.TempDir()
	if err := InstallYARAX(tmp); err != nil {
		t.Fatalf("InstallYARAX: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "yr"))
	if err != nil {
		t.Fatalf("read installed yr: %v", err)
	}
	if !bytes.Equal(got, yrBody) {
		t.Errorf("installed yr content mismatch: got %q, want %q", got, yrBody)
	}
}

func TestInstallYARAX_ChecksumMismatchFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("InstallYARAX windows path uses zip, not tar.gz")
	}

	// Build a real tar archive but advertise the wrong digest in the API
	// response. InstallYARAX should reject the download.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	body := []byte("good-yr")
	hdr := &tar.Header{Name: "yr", Mode: 0o755, Size: int64(len(body))}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(body)
	tw.Close()
	gw.Close()
	archive := buf.Bytes()

	wrongSum := sha256.Sum256([]byte("not-the-archive"))
	asset, err := yaraXAsset()
	if err != nil {
		t.Skipf("YARA-X asset name unavailable: %v", err)
	}

	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"assets": []map[string]any{
				{
					"name":                 asset,
					"browser_download_url": srvURL + "/assets/bin",
					"digest":               "sha256:" + hex.EncodeToString(wrongSum[:]),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/assets/bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()
	origAPI := yaraXReleaseAPI
	yaraXReleaseAPI = srv.URL + "/api"
	defer func() { yaraXReleaseAPI = origAPI }()

	tmp := t.TempDir()
	err = InstallYARAX(tmp)
	if err == nil {
		t.Fatal("InstallYARAX should reject mismatched checksum")
	}
	if !strings.Contains(err.Error(), "checksum") && !strings.Contains(err.Error(), "mismatch") &&
		!strings.Contains(err.Error(), "SHA-256") && !strings.Contains(err.Error(), "sha256") {
		t.Errorf("expected checksum-related error, got: %v", err)
	}
	// Confirm no `yr` binary was placed.
	if _, statErr := os.Stat(filepath.Join(tmp, "yr")); statErr == nil {
		t.Error("yr should not have been installed when checksum failed")
	}
}

func TestYaraXAsset_PlatformNaming(t *testing.T) {
	asset, err := yaraXAsset()
	if err != nil {
		t.Skipf("unsupported platform for YARA-X asset mapping: %v", err)
	}
	if !strings.HasPrefix(asset, "yara-x-"+YARAXVersion+"-") {
		t.Errorf("yaraXAsset = %q, expected prefix yara-x-%s-", asset, YARAXVersion)
	}
	switch {
	case goos() == "linux" && goarch() == "amd64":
		if asset != "yara-x-"+YARAXVersion+"-x86_64-unknown-linux-gnu.gz" {
			t.Errorf("linux/amd64 yaraXAsset = %q (expected x86_64-unknown-linux-gnu.gz)", asset)
		}
	case goos() == "darwin" && goarch() == "arm64":
		if asset != "yara-x-"+YARAXVersion+"-aarch64-apple-darwin.gz" {
			t.Errorf("darwin/arm64 yaraXAsset = %q (expected aarch64-apple-darwin.gz)", asset)
		}
	case goos() == "windows" && goarch() == "amd64":
		if asset != "yara-x-"+YARAXVersion+"-x86_64-pc-windows-msvc.zip" {
			t.Errorf("windows/amd64 yaraXAsset = %q (expected x86_64-pc-windows-msvc.zip)", asset)
		}
	}
}
