package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultToolsDirEndsWithCbomTools(t *testing.T) {
	dir := DefaultToolsDir()
	if !strings.HasSuffix(dir, filepath.Join(".cbom", "tools")) {
		t.Errorf("expected DefaultToolsDir to end with .cbom/tools, got %s", dir)
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
