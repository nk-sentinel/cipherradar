package container

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	imgtypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
	crtypes "github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// staticLayer wraps a tar byte buffer as a v1.Layer suitable for test images.
type staticLayer struct {
	content []byte
	diffID  v1.Hash
	digest  v1.Hash
	size    int64
}

func newStaticLayer(tarContent []byte) (*staticLayer, error) {
	diffID, size, err := v1.SHA256(bytes.NewReader(tarContent))
	if err != nil {
		return nil, err
	}
	return &staticLayer{content: tarContent, diffID: diffID, digest: diffID, size: size}, nil
}

func (l *staticLayer) Digest() (v1.Hash, error) { return l.digest, nil }
func (l *staticLayer) DiffID() (v1.Hash, error) { return l.diffID, nil }
func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.content)), nil
}
func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.content)), nil
}
func (l *staticLayer) Size() (int64, error) { return l.size, nil }
func (l *staticLayer) MediaType() (imgtypes.MediaType, error) {
	return imgtypes.OCILayer, nil
}

var _ v1.Layer = (*staticLayer)(nil)

// tarEntry is one file in a synthetic layer.
type tarEntry struct {
	name    string
	content []byte
}

// buildTar creates an in-memory tar archive from ordered entries (order matters
// for whiteout tests).
func buildTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if _, err := tw.Write(e.content); err != nil {
			t.Fatalf("tar write %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// imageFromLayers builds a v1.Image from one tar-bytes blob per layer.
func imageFromLayers(t *testing.T, layerTars ...[]byte) v1.Image {
	t.Helper()
	img := empty.Image
	for _, lt := range layerTars {
		layer, err := newStaticLayer(lt)
		if err != nil {
			t.Fatalf("static layer: %v", err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			t.Fatalf("append layer: %v", err)
		}
	}
	return img
}

// createTestImageTar writes a single-layer image to a local tar file.
func createTestImageTar(t *testing.T, files map[string][]byte) string {
	t.Helper()
	entries := make([]tarEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, tarEntry{name, content})
	}
	img := imageFromLayers(t, buildTar(t, entries...))

	tarPath := filepath.Join(t.TempDir(), "test-image.tar")
	tag, err := name.NewTag("test/image:latest")
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("write image tarball: %v", err)
	}
	return tarPath
}

func TestScanImage_LocalTar_PythonHashlib(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		"app/main.py": []byte("import hashlib\nh = hashlib.md5(b\"hello\")\n"),
	})

	result, err := ScanImage(tarPath, scannerinit.DefaultRegistry(), []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from Python hashlib usage")
	}
	for _, f := range result.Findings {
		if f.Properties.MaterialType != "container-layer" {
			t.Errorf("MaterialType = %q, want container-layer", f.Properties.MaterialType)
		}
		if !strings.Contains(f.Description, "[layer: ") {
			t.Errorf("description should carry layer provenance, got %q", f.Description)
		}
	}
	if result.FilesScanned == 0 {
		t.Error("expected at least one file scanned")
	}
}

func TestScanImage_EmptyImage(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "empty-image.tar")
	tag, _ := name.NewTag("test/empty:latest")
	if err := tarball.WriteToFile(tarPath, tag, empty.Image); err != nil {
		t.Fatalf("write empty image: %v", err)
	}
	result, err := ScanImage(tarPath, scannerinit.DefaultRegistry(), []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings from empty image, got %d", len(result.Findings))
	}
}

func TestScanImage_MultipleFiles_SortedWithProvenance(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		"app/crypto.py": []byte("import hashlib\nh = hashlib.sha512(b\"t\")\n"),
		"srv/server.go": []byte("package main\nimport \"crypto/aes\"\nvar key []byte\nfunc main() { _, _ = aes.NewCipher(key) }\n"),
	})
	result, err := ScanImage(tarPath, scannerinit.DefaultRegistry(), []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from multiple source files")
	}
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Location.File > result.Findings[i].Location.File {
			t.Errorf("findings not sorted by file: %s > %s",
				result.Findings[i-1].Location.File, result.Findings[i].Location.File)
		}
	}
}

func TestScanImage_WithStubScanner(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{"app.py": []byte("import hashlib")})
	reg := scanner.NewRegistry()
	reg.Register(&stubScanner{})
	result, err := ScanImage(tarPath, reg, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Properties.MaterialType != "container-layer" {
		t.Errorf("MaterialType = %q, want container-layer", result.Findings[0].Properties.MaterialType)
	}
}

// --- ExtractToDir (materialization) tests ---

func TestExtractToDir_RejectsTarSlip(t *testing.T) {
	// A layer whose entry tries to escape the extraction root.
	img := imageFromLayers(t, buildTar(t,
		tarEntry{"../../etc/evil.py", []byte("import hashlib\n")},
		tarEntry{"app/ok.py", []byte("import hashlib\n")},
	))
	dir, layerOf, errs, err := ExtractToDir(img)
	if err != nil {
		t.Fatalf("ExtractToDir: %v", err)
	}
	defer os.RemoveAll(dir)

	// The safe file is materialized under the root.
	if _, ok := layerOf["app/ok.py"]; !ok {
		t.Errorf("safe file should be extracted; layerOf=%v", layerOf)
	}
	// The escaping entry is neither written outside the root nor recorded.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "etc", "evil.py")); err == nil {
		t.Error("tar-slip entry escaped the extraction root!")
	}
	sawSkip := false
	for _, e := range errs {
		if strings.Contains(e.Message, "unsafe tar path") {
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Errorf("expected an 'unsafe tar path' extraction error, got %v", errs)
	}
}

func TestExtractToDir_WhiteoutDeletes(t *testing.T) {
	// Lower layer writes a file; upper layer whites it out.
	lower := buildTar(t, tarEntry{"app/secret.py", []byte("import hashlib\n")}, tarEntry{"app/keep.py", []byte("x=1\n")})
	upper := buildTar(t, tarEntry{"app/.wh.secret.py", []byte("")})
	img := imageFromLayers(t, lower, upper)

	dir, layerOf, _, err := ExtractToDir(img)
	if err != nil {
		t.Fatalf("ExtractToDir: %v", err)
	}
	defer os.RemoveAll(dir)

	if _, err := os.Stat(filepath.Join(dir, "app", "secret.py")); !os.IsNotExist(err) {
		t.Errorf("whiteout should have removed app/secret.py, stat err=%v", err)
	}
	if _, ok := layerOf["app/secret.py"]; ok {
		t.Error("whiteout should have removed app/secret.py from provenance map")
	}
	if _, err := os.Stat(filepath.Join(dir, "app", "keep.py")); err != nil {
		t.Errorf("app/keep.py should survive: %v", err)
	}
}

func TestExtractToDir_MaterializesBinaries(t *testing.T) {
	// Binaries are no longer pre-filtered — they must reach disk so Pass 3 can
	// scan them (gh #83).
	img := imageFromLayers(t, buildTar(t,
		tarEntry{"usr/lib/libcrypto.so", []byte("ELF\x00\x00 fake binary with AES constants")},
	))
	dir, layerOf, _, err := ExtractToDir(img)
	if err != nil {
		t.Fatalf("ExtractToDir: %v", err)
	}
	defer os.RemoveAll(dir)

	if _, ok := layerOf["usr/lib/libcrypto.so"]; !ok {
		t.Errorf("binary should be materialized, not pre-filtered; layerOf=%v", layerOf)
	}
	if _, err := os.Stat(filepath.Join(dir, "usr", "lib", "libcrypto.so")); err != nil {
		t.Errorf("binary should exist on disk: %v", err)
	}
}

func TestSanitizeEntryPath(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
		want   string
	}{
		{"app/main.py", true, "app/main.py"},
		{"/abs/path.py", true, "abs/path.py"},
		{"./a/b.py", true, "a/b.py"},
		{"../escape", false, ""},
		{"a/../../escape", false, ""},
		{"", false, ""},
	}
	for _, c := range cases {
		got, ok := sanitizeEntryPath(c.in)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("sanitizeEntryPath(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestIsLocalTar(t *testing.T) {
	for _, in := range []string{"nginx:latest", "gcr.io/project/image:tag", "/nonexistent/path.tar", "image.tar"} {
		if isLocalTar(in) {
			t.Errorf("isLocalTar(%q) = true, want false", in)
		}
	}
	tmpFile := filepath.Join(t.TempDir(), "test.tar")
	if err := os.WriteFile(tmpFile, []byte("fake tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isLocalTar(tmpFile) {
		t.Errorf("isLocalTar(%q) = false, want true", tmpFile)
	}
}

// stubScanner is a minimal scanner for testing that matches .py files.
type stubScanner struct{}

func (s *stubScanner) Name() string         { return "stub" }
func (s *stubScanner) Extensions() []string { return []string{".py"} }
func (s *stubScanner) ScanFile(path string, content []byte) ([]crtypes.Finding, error) {
	if bytes.Contains(content, []byte("hashlib")) {
		return []crtypes.Finding{{
			Name:      "MD5",
			AssetType: crtypes.AssetAlgorithm,
			Location:  crtypes.Location{File: path, StartLine: 1},
		}}, nil
	}
	return nil, nil
}
