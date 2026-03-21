package binary_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ---------------------------------------------------------------------------
// Wheel scanner interface tests
// ---------------------------------------------------------------------------

func TestWheelScannerName(t *testing.T) {
	s := binary.NewWheelScanner()
	if s.Name() != "wheel" {
		t.Errorf("expected Name() = %q, got %q", "wheel", s.Name())
	}
}

func TestWheelScannerExtensions(t *testing.T) {
	s := binary.NewWheelScanner()
	exts := s.Extensions()
	expected := map[string]bool{
		".whl": true, ".egg": true,
	}
	if len(exts) != len(expected) {
		t.Fatalf("expected %d extensions, got %d: %v", len(expected), len(exts), exts)
	}
	for _, ext := range exts {
		if !expected[ext] {
			t.Errorf("unexpected extension %q", ext)
		}
	}
}

func TestWheelScannerEmptyContent(t *testing.T) {
	s := binary.NewWheelScanner()
	findings, err := s.ScanFile("test.whl", []byte{})
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty content, got %d", len(findings))
	}
}

func TestWheelScannerInvalidZip(t *testing.T) {
	s := binary.NewWheelScanner()
	_, err := s.ScanFile("bad.whl", []byte("not a zip file"))
	if err == nil {
		t.Error("expected error for invalid ZIP content")
	}
}

// ---------------------------------------------------------------------------
// Wheel with Python files using crypto
// ---------------------------------------------------------------------------

func TestWheelScannerDetectsPythonCrypto(t *testing.T) {
	s := binary.NewWheelScanner()

	pythonCode := []byte(`
import hashlib
import ssl

def compute_hash(data):
    return hashlib.md5(data).hexdigest()

def get_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx
`)

	whlContent := createTestWheel(t, map[string][]byte{
		"mypackage/__init__.py":  []byte(""),
		"mypackage/crypto_util.py": pythonCode,
	})

	findings, err := s.ScanFile("mypackage-1.0.0.whl", whlContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should detect hashlib.md5
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Properties.Primitive == "hash"
	}, "MD5 via hashlib in Python file inside wheel")
}

// ---------------------------------------------------------------------------
// Wheel with C extension (.so) containing crypto
// ---------------------------------------------------------------------------

func TestWheelScannerDetectsCExtensionCrypto(t *testing.T) {
	s := binary.NewWheelScanner()

	// Create a fake .so file with AES S-box
	soData := make([]byte, 1024)
	for i := range soData {
		soData[i] = byte(i % 251)
	}
	aesSbox := []byte{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
		0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
		0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
		0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
		0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	}
	copy(soData[512:], aesSbox)

	whlContent := createTestWheel(t, map[string][]byte{
		"mypackage/__init__.py":   []byte(""),
		"mypackage/_native.so":    soData,
	})

	findings, err := s.ScanFile("mypackage-1.0.0.whl", whlContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher"
	}, "AES S-box in .so C extension inside wheel")
}

// ---------------------------------------------------------------------------
// Wheel with .pyd extension (Windows Python extension)
// ---------------------------------------------------------------------------

func TestWheelScannerDetectsPydExtension(t *testing.T) {
	s := binary.NewWheelScanner()

	// Create a fake .pyd with RSA OID
	pydData := make([]byte, 256)
	for i := range pydData {
		pydData[i] = 0x00
	}
	rsaOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01}
	copy(pydData[50:], rsaOID)

	whlContent := createTestWheel(t, map[string][]byte{
		"mypackage/__init__.py":   []byte(""),
		"mypackage/_rsa.pyd":     pydData,
	})

	findings, err := s.ScanFile("mypackage-1.0.0.whl", whlContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa"
	}, "RSA OID in .pyd extension inside wheel")
}

// ---------------------------------------------------------------------------
// Wheel with mixed Python + native
// ---------------------------------------------------------------------------

func TestWheelScannerMixedContent(t *testing.T) {
	s := binary.NewWheelScanner()

	pythonCode := []byte(`
import hashlib

def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()
`)

	soData := make([]byte, 512)
	for i := range soData {
		soData[i] = 0xAA
	}
	md5T := []byte{
		0x78, 0xa4, 0x6a, 0xd7,
		0x56, 0xb7, 0xc7, 0xe8,
		0xdb, 0x70, 0x20, 0x24,
		0xee, 0xce, 0xbd, 0xc1,
		0xaf, 0x0f, 0x7c, 0xf5,
		0x2a, 0xc6, 0x87, 0x47,
		0x13, 0x46, 0x30, 0xa8,
		0x01, 0x95, 0x46, 0xfd,
	}
	copy(soData[100:], md5T)

	whlContent := createTestWheel(t, map[string][]byte{
		"mypackage/__init__.py":   []byte(""),
		"mypackage/hasher.py":     pythonCode,
		"mypackage/_md5_native.so": soData,
	})

	findings, err := s.ScanFile("mypackage-1.0.0.whl", whlContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should find SHA-256 from Python source
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash"
	}, "SHA-256 from Python source in wheel")

	// Should find MD5 from C extension
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5"
	}, "MD5 from native .so in wheel")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// createTestWheel creates an in-memory ZIP archive simulating a Python wheel.
func createTestWheel(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create ZIP entry %s: %v", name, err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatalf("failed to write ZIP entry %s: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close ZIP writer: %v", err)
	}

	return buf.Bytes()
}
