package binary_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ---------------------------------------------------------------------------
// JAR scanner interface tests
// ---------------------------------------------------------------------------

func TestJARScannerName(t *testing.T) {
	s := binary.NewJARScanner()
	if s.Name() != "jar" {
		t.Errorf("expected Name() = %q, got %q", "jar", s.Name())
	}
}

func TestJARScannerExtensions(t *testing.T) {
	s := binary.NewJARScanner()
	exts := s.Extensions()
	expected := map[string]bool{
		".jar": true, ".war": true, ".ear": true, ".zip": true,
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

func TestJARScannerEmptyContent(t *testing.T) {
	s := binary.NewJARScanner()
	findings, err := s.ScanFile("test.jar", []byte{})
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty content, got %d", len(findings))
	}
}

func TestJARScannerInvalidZip(t *testing.T) {
	s := binary.NewJARScanner()
	_, err := s.ScanFile("bad.jar", []byte("not a zip file"))
	if err == nil {
		t.Error("expected error for invalid ZIP content")
	}
}

// ---------------------------------------------------------------------------
// JAR with .class containing crypto constants
// ---------------------------------------------------------------------------

func TestJARScannerDetectsClassCrypto(t *testing.T) {
	s := binary.NewJARScanner()

	// Create a synthetic JAR (ZIP) with a .class file containing AES S-box bytes
	jarContent := createTestJAR(t, map[string][]byte{
		"com/example/Crypto.class": buildClassWithAESSbox(),
	})

	findings, err := s.ScanFile("test.jar", jarContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher"
	}, "AES detection in .class file inside JAR")
}

// ---------------------------------------------------------------------------
// JAR with config files
// ---------------------------------------------------------------------------

func TestJARScannerDetectsConfigSecrets(t *testing.T) {
	s := binary.NewJARScanner()

	propertiesContent := []byte("db.password=supersecret123\ndb.url=jdbc:mysql://localhost/mydb\n")

	jarContent := createTestJAR(t, map[string][]byte{
		"META-INF/MANIFEST.MF":   []byte("Manifest-Version: 1.0\n"),
		"application.properties": propertiesContent,
	})

	findings, err := s.ScanFile("app.jar", jarContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetRelatedCryptoMaterial &&
			f.Severity == types.SeverityHigh
	}, "Hardcoded secret in .properties inside JAR")
}

// ---------------------------------------------------------------------------
// JAR with XML config containing crypto references
// ---------------------------------------------------------------------------

func TestJARScannerDetectsXMLCryptoRefs(t *testing.T) {
	s := binary.NewJARScanner()

	xmlContent := []byte(`<?xml version="1.0"?>
<config>
  <ssl protocol="SSLv3" />
  <cipher>DES</cipher>
</config>`)

	jarContent := createTestJAR(t, map[string][]byte{
		"META-INF/security.xml": xmlContent,
	})

	findings, err := s.ScanFile("app.jar", jarContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should detect SSLv3 or DES references
	foundCryptoRef := false
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "tls" || f.Properties.AlgorithmFamily == "des" {
			foundCryptoRef = true
			break
		}
	}
	if !foundCryptoRef {
		t.Error("expected to find crypto reference in XML config inside JAR")
	}
}

// ---------------------------------------------------------------------------
// JAR with multiple entry types
// ---------------------------------------------------------------------------

func TestJARScannerMultipleEntryTypes(t *testing.T) {
	s := binary.NewJARScanner()

	jarContent := createTestJAR(t, map[string][]byte{
		"com/example/Main.class": buildClassWithRSAOID(),
		"config.properties":      []byte("api.secret_key=abc123xyz\n"),
		"META-INF/MANIFEST.MF":   []byte("Manifest-Version: 1.0\n"),
	})

	findings, err := s.ScanFile("multi.war", jarContent)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should find RSA OID in .class
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa"
	}, "RSA OID in .class file")

	// Should find hardcoded secret in .properties
	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetRelatedCryptoMaterial
	}, "Hardcoded secret in .properties")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// createTestJAR creates an in-memory ZIP/JAR archive from a map of
// filename -> content pairs.
func createTestJAR(t *testing.T, files map[string][]byte) []byte {
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

// buildClassWithAESSbox creates a fake .class file with the AES S-box bytes
// embedded, simulating a compiled Java class that uses AES.
func buildClassWithAESSbox() []byte {
	// Start with a valid Java class file magic number
	data := make([]byte, 1024)
	// Java class file magic: 0xCAFEBABE
	data[0] = 0xCA
	data[1] = 0xFE
	data[2] = 0xBA
	data[3] = 0xBE

	// Embed AES S-box at offset 256
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
	copy(data[256:], aesSbox)

	return data
}

// buildClassWithRSAOID creates a fake .class file with the RSA OID embedded.
func buildClassWithRSAOID() []byte {
	data := make([]byte, 512)
	data[0] = 0xCA
	data[1] = 0xFE
	data[2] = 0xBA
	data[3] = 0xBE

	rsaOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01}
	copy(data[100:], rsaOID)

	return data
}
