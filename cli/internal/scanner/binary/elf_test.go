package binary_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	binarypkg "github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ---------------------------------------------------------------------------
// ELFScanner interface tests
// ---------------------------------------------------------------------------

func TestELFScannerName(t *testing.T) {
	s := binarypkg.NewELFScanner()
	if s.Name() != "elf" {
		t.Errorf("expected Name() = %q, got %q", "elf", s.Name())
	}
}

func TestELFScannerExtensions(t *testing.T) {
	s := binarypkg.NewELFScanner()
	exts := s.Extensions()
	expected := map[string]bool{
		".so": true, ".dll": true, ".dylib": true, ".exe": true,
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

func TestELFScanner_EmptyContent(t *testing.T) {
	s := binarypkg.NewELFScanner()
	findings, err := s.ScanFile("test.so", []byte{})
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty content, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Non-ELF binary fallback: byte-pattern scanning
// ---------------------------------------------------------------------------

func TestELFScanner_NonELFBinaryFallback(t *testing.T) {
	s := binarypkg.NewELFScanner()

	// Create a non-ELF binary with AES S-box embedded.
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 251)
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
	copy(data[512:], aesSbox)

	findings, err := s.ScanFile("libcrypto.dll", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	elfAssertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher"
	}, "AES S-box detection in non-ELF binary")
}

// ---------------------------------------------------------------------------
// Go binary detection: crypto package imports
// ---------------------------------------------------------------------------

func TestELFScanner_GoBinaryDetection(t *testing.T) {
	s := binarypkg.NewELFScanner()

	// Build a fake binary that looks like a Go binary (contains the magic
	// marker and crypto package paths).
	var buf bytes.Buffer
	// Pad with noise.
	buf.Write(bytes.Repeat([]byte{0xCC}, 256))
	// Go buildinfo magic.
	buf.Write([]byte("\xff Go buildinf:"))
	buf.Write(bytes.Repeat([]byte{0x00}, 64))
	// Go version string.
	buf.Write([]byte("go1.22.3"))
	buf.Write([]byte{0x00})
	// Crypto package paths.
	buf.Write([]byte("crypto/aes"))
	buf.Write(bytes.Repeat([]byte{0x00}, 16))
	buf.Write([]byte("crypto/sha256"))
	buf.Write(bytes.Repeat([]byte{0x00}, 16))
	buf.Write([]byte("crypto/rsa"))
	buf.Write(bytes.Repeat([]byte{0x00}, 64))

	content := buf.Bytes()

	findings, err := s.ScanFile("myapp.exe", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	elfAssertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Name == "AES (Go stdlib)"
	}, "Go AES package detection")

	elfAssertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Name == "SHA-256 (Go stdlib)"
	}, "Go SHA-256 package detection")

	elfAssertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Go RSA package with quantum-vulnerable status")
}

func TestELFScanner_NonGoBinaryNoGoFindings(t *testing.T) {
	s := binarypkg.NewELFScanner()

	// A non-Go binary should produce no Go-specific findings.
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 251)
	}

	findings, err := s.ScanFile("native.so", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "cbom-binary-go-aes" || f.RuleID == "cbom-binary-go-rsa" {
			t.Errorf("unexpected Go-specific finding in non-Go binary: %s", f.RuleID)
		}
	}
}

// ---------------------------------------------------------------------------
// ELF binary with crypto in data sections
// ---------------------------------------------------------------------------

func TestELFScanner_CraftedELFWithRodata(t *testing.T) {
	// Build a minimal valid ELF binary with a .rodata section containing
	// an AES S-box. This tests the ELF section parsing path.
	elfBytes := buildMinimalELF(t)

	s := binarypkg.NewELFScanner()
	findings, err := s.ScanFile("libcrypto.so", elfBytes)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	elfAssertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher"
	}, "AES S-box in ELF .rodata section")
}

func TestELFScanner_MultiplePatternsInNativeBinary(t *testing.T) {
	s := binarypkg.NewELFScanner()

	data := make([]byte, 2048)
	for i := range data {
		data[i] = 0xCC
	}

	// Embed AES S-box.
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
	copy(data[100:], aesSbox)

	// Embed MD5 T-table.
	md5T := []byte{
		0x78, 0xa4, 0x6a, 0xd7,
		0x56, 0xb7, 0xc7, 0xe8,
		0xdb, 0x70, 0x20, 0x24,
		0xee, 0xce, 0xbd, 0xc1,
	}
	copy(data[1500:], md5T)

	findings, err := s.ScanFile("multi.dll", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	foundAES := false
	foundMD5 := false
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "aes" {
			foundAES = true
		}
		if f.Properties.AlgorithmFamily == "md5" {
			foundMD5 = true
		}
	}

	if !foundAES {
		t.Error("expected to find AES pattern in native binary")
	}
	if !foundMD5 {
		t.Error("expected to find MD5 pattern in native binary")
	}
}

func TestELFScanner_GoTLSProtocol(t *testing.T) {
	s := binarypkg.NewELFScanner()

	// Build a fake Go binary that imports crypto/tls.
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte{0xAA}, 128))
	buf.Write([]byte("\xff Go buildinf:"))
	buf.Write(bytes.Repeat([]byte{0x00}, 32))
	buf.Write([]byte("go1.21.0"))
	buf.Write([]byte{0x00})
	buf.Write([]byte("crypto/tls"))
	buf.Write(bytes.Repeat([]byte{0x00}, 64))

	findings, err := s.ScanFile("server.exe", buf.Bytes())
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	elfAssertFindingExists(t, findings, func(f types.Finding) bool {
		return f.AssetType == types.AssetProtocol &&
			f.Properties.ProtocolType == "tls" &&
			f.RuleID == "cbom-binary-go-tls"
	}, "Go TLS protocol detection")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func elfAssertFindingExists(t *testing.T, findings []types.Finding, match func(types.Finding) bool, description string) {
	t.Helper()
	for _, f := range findings {
		if match(f) {
			return
		}
	}
	t.Errorf("expected to find: %s", description)
	t.Logf("findings were:")
	for _, f := range findings {
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Family=%s Primitive=%s QS=%s AssetType=%s",
			f.ID, f.Name, f.RuleID, f.Severity,
			f.Properties.AlgorithmFamily, f.Properties.Primitive,
			f.Properties.QuantumStatus, f.AssetType)
	}
}

// buildMinimalELF creates a minimal valid ELF64 binary with a .rodata section
// containing the AES S-box for testing purposes.
func buildMinimalELF(t *testing.T) []byte {
	t.Helper()

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

	// Section name string table: \0 + ".rodata\0" + ".shstrtab\0"
	shstrtab := []byte("\x00.rodata\x00.shstrtab\x00")
	rodataNameIdx := uint32(1)      // offset of ".rodata" in shstrtab
	shstrtabNameIdx := uint32(9)    // offset of ".shstrtab" in shstrtab

	// Layout:
	// [0..63]     ELF header (64 bytes for ELF64)
	// [64..127]   .rodata data (AES S-box, 64 bytes)
	// [128..147]  .shstrtab data (shstrtab, 20 bytes)
	// [148..]     Section headers (3 sections: null + .rodata + .shstrtab)

	rodataOffset := uint64(64)
	rodataSize := uint64(len(aesSbox))
	shstrtabOffset := rodataOffset + rodataSize
	shstrtabSize := uint64(len(shstrtab))

	// Align section headers to 8 bytes.
	shdrOffset := shstrtabOffset + shstrtabSize
	if shdrOffset%8 != 0 {
		shdrOffset = (shdrOffset/8 + 1) * 8
	}

	// Each section header is 64 bytes for ELF64. 3 sections.
	ehdrSize := uint16(64)
	shentSize := uint16(64)
	shnum := uint16(3)
	shstrndx := uint16(2) // .shstrtab is section index 2

	var buf bytes.Buffer

	// --- ELF Header (64 bytes) ---
	// e_ident (16 bytes)
	buf.Write([]byte{0x7f, 'E', 'L', 'F'}) // magic
	buf.WriteByte(2)                         // EI_CLASS: ELFCLASS64
	buf.WriteByte(1)                         // EI_DATA: ELFDATA2LSB (little-endian)
	buf.WriteByte(1)                         // EI_VERSION: EV_CURRENT
	buf.WriteByte(0)                         // EI_OSABI
	buf.Write(make([]byte, 8))               // padding

	// e_type (2) - ET_EXEC
	binary.Write(&buf, binary.LittleEndian, uint16(elf.ET_EXEC))
	// e_machine (2) - EM_X86_64
	binary.Write(&buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	// e_version (4)
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	// e_entry (8)
	binary.Write(&buf, binary.LittleEndian, uint64(0))
	// e_phoff (8) - no program headers
	binary.Write(&buf, binary.LittleEndian, uint64(0))
	// e_shoff (8)
	binary.Write(&buf, binary.LittleEndian, shdrOffset)
	// e_flags (4)
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// e_ehsize (2)
	binary.Write(&buf, binary.LittleEndian, ehdrSize)
	// e_phentsize (2)
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	// e_phnum (2)
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	// e_shentsize (2)
	binary.Write(&buf, binary.LittleEndian, shentSize)
	// e_shnum (2)
	binary.Write(&buf, binary.LittleEndian, shnum)
	// e_shstrndx (2)
	binary.Write(&buf, binary.LittleEndian, shstrndx)

	// --- .rodata section data ---
	buf.Write(aesSbox)

	// --- .shstrtab section data ---
	buf.Write(shstrtab)

	// --- Padding to align section headers ---
	for uint64(buf.Len()) < shdrOffset {
		buf.WriteByte(0)
	}

	// --- Section headers ---

	// Section 0: null section (all zeros, 64 bytes)
	buf.Write(make([]byte, 64))

	// Section 1: .rodata
	writeSectionHeader(&buf, rodataNameIdx, uint32(elf.SHT_PROGBITS), uint64(elf.SHF_ALLOC),
		0, rodataOffset, rodataSize, 0, 0, 1, 0)

	// Section 2: .shstrtab
	writeSectionHeader(&buf, shstrtabNameIdx, uint32(elf.SHT_STRTAB), 0,
		0, shstrtabOffset, shstrtabSize, 0, 0, 1, 0)

	return buf.Bytes()
}

// writeSectionHeader writes an ELF64 section header to the buffer.
func writeSectionHeader(buf *bytes.Buffer, name uint32, shtype uint32, flags uint64,
	addr uint64, offset uint64, size uint64, link uint32, info uint32,
	addralign uint64, entsize uint64) {
	binary.Write(buf, binary.LittleEndian, name)
	binary.Write(buf, binary.LittleEndian, shtype)
	binary.Write(buf, binary.LittleEndian, flags)
	binary.Write(buf, binary.LittleEndian, addr)
	binary.Write(buf, binary.LittleEndian, offset)
	binary.Write(buf, binary.LittleEndian, size)
	binary.Write(buf, binary.LittleEndian, link)
	binary.Write(buf, binary.LittleEndian, info)
	binary.Write(buf, binary.LittleEndian, addralign)
	binary.Write(buf, binary.LittleEndian, entsize)
}
