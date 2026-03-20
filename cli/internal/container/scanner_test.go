package container

import (
	"archive/tar"
	"bytes"
	"fmt"
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
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
	crtypes "github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// staticLayer wraps a tar byte buffer as a v1.Layer suitable for test images.
type staticLayer struct {
	content  []byte
	diffID   v1.Hash
	digest   v1.Hash
	size     int64
}

func newStaticLayer(tarContent []byte) (*staticLayer, error) {
	diffID, size, err := v1.SHA256(bytes.NewReader(tarContent))
	if err != nil {
		return nil, err
	}
	return &staticLayer{
		content: tarContent,
		diffID:  diffID,
		digest:  diffID, // uncompressed, so same
		size:    size,
	}, nil
}

func (l *staticLayer) Digest() (v1.Hash, error)                          { return l.digest, nil }
func (l *staticLayer) DiffID() (v1.Hash, error)                          { return l.diffID, nil }
func (l *staticLayer) Compressed() (io.ReadCloser, error)                { return io.NopCloser(bytes.NewReader(l.content)), nil }
func (l *staticLayer) Uncompressed() (io.ReadCloser, error)              { return io.NopCloser(bytes.NewReader(l.content)), nil }
func (l *staticLayer) Size() (int64, error)                              { return l.size, nil }
func (l *staticLayer) MediaType() (types.MediaType, error)               { return types.OCILayer, nil }

// Verify staticLayer implements v1.Layer.
var _ v1.Layer = (*staticLayer)(nil)

// buildTarBytes creates an in-memory tar archive containing the given files.
func buildTarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for fname, content := range files {
		hdr := &tar.Header{
			Name:     fname,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing tar header for %s: %v", fname, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("writing tar content for %s: %v", fname, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	return buf.Bytes()
}

// createTestImageTar builds a minimal OCI tar image containing the given files
// and writes it to a temporary file. Returns the path to the tar file.
func createTestImageTar(t *testing.T, files map[string][]byte) string {
	t.Helper()

	tarBytes := buildTarBytes(t, files)
	layer, err := newStaticLayer(tarBytes)
	if err != nil {
		t.Fatalf("creating static layer: %v", err)
	}

	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("appending layer: %v", err)
	}

	tarPath := filepath.Join(t.TempDir(), "test-image.tar")
	tag, err := name.NewTag("test/image:latest")
	if err != nil {
		t.Fatalf("creating tag: %v", err)
	}
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("writing image tarball: %v", err)
	}

	return tarPath
}

func TestScanImage_LocalTar_PythonHashlib(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		"app/main.py": []byte("import hashlib\nh = hashlib.md5(b\"hello\")\n"),
	})

	registry := scannerinit.DefaultRegistry()
	result, err := ScanImage(tarPath, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding from Python hashlib usage")
	}

	// Verify layer attribution.
	for _, f := range result.Findings {
		if f.Properties.MaterialType != "container-layer" {
			t.Errorf("finding %s: MaterialType = %q, want %q", f.ID, f.Properties.MaterialType, "container-layer")
		}
		if !strings.Contains(f.Description, "[layer: ") {
			t.Errorf("finding %s: description should contain layer digest, got %q", f.ID, f.Description)
		}
	}

	if result.FilesScanned == 0 {
		t.Error("expected at least one file scanned")
	}
}

func TestScanImage_EmptyImage(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "empty-image.tar")

	tag, err := name.NewTag("test/empty:latest")
	if err != nil {
		t.Fatalf("creating tag: %v", err)
	}
	if err := tarball.WriteToFile(tarPath, tag, empty.Image); err != nil {
		t.Fatalf("writing empty image tarball: %v", err)
	}

	registry := scannerinit.DefaultRegistry()
	result, err := ScanImage(tarPath, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings from empty image, got %d", len(result.Findings))
	}
	if result.FilesScanned != 0 {
		t.Errorf("expected 0 files scanned, got %d", result.FilesScanned)
	}
}

func TestScanImage_BinaryFileSkipping(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		// Binary file (should be skipped by extension).
		"app/binary.exe": []byte("MZ\x00\x00this is a fake exe"),
		// Binary content (null bytes, should be skipped).
		"app/data.txt": {0x00, 0x01, 0x02, 0x03, 0x00},
		// Scannable source file.
		"app/main.py": []byte("import hashlib\nh = hashlib.sha256(b\"data\")\n"),
	})

	registry := scannerinit.DefaultRegistry()
	result, err := ScanImage(tarPath, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	// Only the Python file should produce findings.
	for _, f := range result.Findings {
		if strings.Contains(f.Location.File, "binary.exe") {
			t.Error("binary.exe should have been skipped")
		}
		if strings.Contains(f.Location.File, "data.txt") {
			t.Error("binary data.txt should have been skipped")
		}
	}
}

func TestScanImage_FileSizeLimit(t *testing.T) {
	// Create a file that exceeds maxFileSize (1 MB).
	largeContent := bytes.Repeat([]byte("import hashlib\n"), maxFileSize/15+1)

	tarPath := createTestImageTar(t, map[string][]byte{
		"app/large.py": largeContent,
		"app/small.py": []byte("import hashlib\nh = hashlib.md5(b\"test\")\n"),
	})

	registry := scannerinit.DefaultRegistry()
	result, err := ScanImage(tarPath, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	// large.py should be skipped; only small.py findings expected.
	for _, f := range result.Findings {
		if strings.Contains(f.Location.File, "large.py") {
			t.Error("large.py should have been skipped due to size limit")
		}
	}
}

func TestScanImage_MultipleFiles(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		"app/crypto.py": []byte("from cryptography.hazmat.primitives.ciphers import Cipher\nimport hashlib\nh = hashlib.sha512(b\"test\")\n"),
		"app/server.go": []byte("package main\nimport \"crypto/aes\"\nfunc main() {\n\tblock, _ := aes.NewCipher(key)\n}\n"),
	})

	registry := scannerinit.DefaultRegistry()
	result, err := ScanImage(tarPath, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected findings from multiple source files")
	}

	// Findings should be sorted by file path.
	for i := 1; i < len(result.Findings); i++ {
		prev := result.Findings[i-1]
		curr := result.Findings[i]
		if prev.Location.File > curr.Location.File {
			t.Errorf("findings not sorted by file: %s > %s", prev.Location.File, curr.Location.File)
		}
	}

	// Sequential IDs should be well-formed.
	for i, f := range result.Findings {
		expected := fmt.Sprintf("FIND-%d", i+1)
		if f.ID != expected {
			t.Errorf("finding %d: ID = %q, want %q", i, f.ID, expected)
		}
	}
}

func TestScanImage_WhiteoutFilesSkipped(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		"app/.wh.deleted.py": []byte("import hashlib\nh = hashlib.md5(b\"data\")\n"),
		"app/real.py":        []byte("import hashlib\nh = hashlib.sha256(b\"data\")\n"),
	})

	registry := scannerinit.DefaultRegistry()
	result, err := ScanImage(tarPath, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	for _, f := range result.Findings {
		if strings.Contains(f.Location.File, ".wh.") {
			t.Error("whiteout file should have been skipped")
		}
	}
}

func TestIsLocalTar(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"nginx:latest", false},
		{"gcr.io/project/image:tag", false},
		{"/nonexistent/path.tar", false},
		{"image.tar", false}, // file doesn't exist
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isLocalTar(tt.input)
			if got != tt.want {
				t.Errorf("isLocalTar(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}

	// Test with an actual file.
	tmpFile := filepath.Join(t.TempDir(), "test.tar")
	if err := os.WriteFile(tmpFile, []byte("fake tar"), 0644); err != nil {
		t.Fatal(err)
	}
	if !isLocalTar(tmpFile) {
		t.Errorf("isLocalTar(%q) = false, want true", tmpFile)
	}
}

func TestIsBinaryExtension(t *testing.T) {
	binaries := []string{"file.exe", "lib.so", "lib.dll", "image.png", "doc.pdf", "archive.zip"}
	for _, f := range binaries {
		if !isBinaryExtension(f) {
			t.Errorf("isBinaryExtension(%q) = false, want true", f)
		}
	}

	sources := []string{"main.py", "app.go", "index.js", "Main.java", "config.yml"}
	for _, f := range sources {
		if isBinaryExtension(f) {
			t.Errorf("isBinaryExtension(%q) = true, want false", f)
		}
	}
}

func TestIsBinaryContent(t *testing.T) {
	if !isBinaryContent([]byte{0x00, 0x01, 0x02}) {
		t.Error("content with null bytes should be detected as binary")
	}
	if isBinaryContent([]byte("import hashlib\n")) {
		t.Error("text content should not be detected as binary")
	}
	if isBinaryContent([]byte{}) {
		t.Error("empty content should not be detected as binary")
	}
}

// stubScanner is a minimal scanner for testing that matches .py files.
type stubScanner struct{}

func (s *stubScanner) Name() string        { return "stub" }
func (s *stubScanner) Extensions() []string { return []string{".py"} }
func (s *stubScanner) ScanFile(path string, content []byte) ([]crtypes.Finding, error) {
	if bytes.Contains(content, []byte("hashlib")) {
		return []crtypes.Finding{{
			Name:        "MD5",
			AssetType:   crtypes.AssetAlgorithm,
			Description: "hashlib usage detected",
			Location:    crtypes.Location{File: path, StartLine: 1},
		}}, nil
	}
	return nil, nil
}

func TestScanImage_WithStubScanner(t *testing.T) {
	tarPath := createTestImageTar(t, map[string][]byte{
		"app.py": []byte("import hashlib"),
	})

	reg := scanner.NewRegistry()
	reg.Register(&stubScanner{})

	result, err := ScanImage(tarPath, reg, []int{1})
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Properties.MaterialType != "container-layer" {
		t.Errorf("MaterialType = %q, want %q", f.Properties.MaterialType, "container-layer")
	}
}
