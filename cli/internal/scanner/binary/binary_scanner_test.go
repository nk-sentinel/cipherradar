package binary_test

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ---------------------------------------------------------------------------
// Interface tests
// ---------------------------------------------------------------------------

func TestBinaryScannerName(t *testing.T) {
	s := binary.New()
	if s.Name() != "binary" {
		t.Errorf("expected Name() = %q, got %q", "binary", s.Name())
	}
}

func TestBinaryScannerExtensions(t *testing.T) {
	s := binary.New()
	exts := s.Extensions()
	expected := map[string]bool{
		".so": true, ".dll": true, ".dylib": true, ".exe": true, ".class": true,
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

func TestEmptyContent(t *testing.T) {
	s := binary.New()
	findings, err := s.ScanFile("test.dll", []byte{})
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty content, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// AES S-box detection
// ---------------------------------------------------------------------------

func TestDetectsAESSbox(t *testing.T) {
	s := binary.New()

	// Build a fake binary with the AES S-box embedded at an offset
	data := make([]byte, 1024)
	// Fill with random-ish noise
	for i := range data {
		data[i] = byte(i % 251)
	}

	// Embed the first 64 bytes of the AES S-box at offset 512
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

	findings, err := s.ScanFile("test.so", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "aes" &&
			f.Properties.Primitive == "block-cipher" &&
			f.Severity == types.SeverityInfo
	}, "AES S-box detection")
}

// ---------------------------------------------------------------------------
// SHA-256 round constants detection
// ---------------------------------------------------------------------------

func TestDetectsSHA256Constants(t *testing.T) {
	s := binary.New()

	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 131)
	}

	sha256K := []byte{
		0x42, 0x8a, 0x2f, 0x98,
		0x71, 0x37, 0x44, 0x91,
		0xb5, 0xc0, 0xfb, 0xcf,
		0xe9, 0xb5, 0xdb, 0xa5,
	}
	copy(data[100:], sha256K)

	findings, err := s.ScanFile("test.dll", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "sha-256" &&
			f.Properties.Primitive == "hash"
	}, "SHA-256 round constants detection")
}

// ---------------------------------------------------------------------------
// DES S-box detection
// ---------------------------------------------------------------------------

func TestDetectsDESSbox(t *testing.T) {
	s := binary.New()

	data := make([]byte, 512)
	for i := range data {
		data[i] = 0xff
	}

	desSbox1 := []byte{
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
	}
	copy(data[200:], desSbox1)

	findings, err := s.ScanFile("test.exe", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "des" &&
			f.Severity == types.SeverityHigh
	}, "DES S-box detection with HIGH severity")
}

// ---------------------------------------------------------------------------
// RSA OID detection
// ---------------------------------------------------------------------------

func TestDetectsRSAOID(t *testing.T) {
	s := binary.New()

	data := make([]byte, 256)
	for i := range data {
		data[i] = 0x00
	}

	rsaOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01}
	copy(data[50:], rsaOID)

	findings, err := s.ScanFile("test.class", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "rsa" &&
			f.Properties.Primitive == "pke" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "RSA OID detection with QuantumVulnerable status")
}

// ---------------------------------------------------------------------------
// MD5 T-table detection
// ---------------------------------------------------------------------------

func TestDetectsMD5Table(t *testing.T) {
	s := binary.New()

	data := make([]byte, 256)
	for i := range data {
		data[i] = 0xAA
	}

	md5T := []byte{
		0x78, 0xa4, 0x6a, 0xd7,
		0x56, 0xb7, 0xc7, 0xe8,
		0xdb, 0x70, 0x20, 0x24,
		0xee, 0xce, 0xbd, 0xc1,
	}
	copy(data[30:], md5T)

	findings, err := s.ScanFile("test.so", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "md5" &&
			f.Severity == types.SeverityHigh
	}, "MD5 T-table detection with HIGH severity")
}

// ---------------------------------------------------------------------------
// Blowfish P-array detection
// ---------------------------------------------------------------------------

func TestDetectsBlowfishParray(t *testing.T) {
	s := binary.New()

	data := make([]byte, 256)
	for i := range data {
		data[i] = 0xBB
	}

	bfP := []byte{
		0x24, 0x3f, 0x6a, 0x88,
		0x85, 0xa3, 0x08, 0xd3,
		0x13, 0x19, 0x8a, 0x2e,
		0x03, 0x70, 0x73, 0x44,
	}
	copy(data[80:], bfP)

	findings, err := s.ScanFile("test.dll", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "blowfish" &&
			f.Severity == types.SeverityMedium
	}, "Blowfish P-array detection with MEDIUM severity")
}

// ---------------------------------------------------------------------------
// No false positives on random data
// ---------------------------------------------------------------------------

func TestNoFalsePositivesOnRandom(t *testing.T) {
	s := binary.New()

	// Create data that doesn't contain any known patterns
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte((i*17 + 31) % 256)
	}

	findings, err := s.ScanFile("random.bin", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings on pseudo-random data, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  - %s (family=%s)", f.Name, f.Properties.AlgorithmFamily)
		}
	}
}

// ---------------------------------------------------------------------------
// Multiple patterns in same file
// ---------------------------------------------------------------------------

func TestMultiplePatternsInSameFile(t *testing.T) {
	s := binary.New()

	data := make([]byte, 2048)
	for i := range data {
		data[i] = 0xCC
	}

	// Embed AES S-box
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

	// Embed RSA OID at a different offset
	rsaOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01}
	copy(data[1500:], rsaOID)

	findings, err := s.ScanFile("multi.dll", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should find both AES and RSA
	foundAES := false
	foundRSA := false
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "aes" {
			foundAES = true
		}
		if f.Properties.AlgorithmFamily == "rsa" {
			foundRSA = true
		}
	}

	if !foundAES {
		t.Error("expected to find AES S-box pattern")
	}
	if !foundRSA {
		t.Error("expected to find RSA OID pattern")
	}
}

// ---------------------------------------------------------------------------
// De-duplication within same family
// ---------------------------------------------------------------------------

func TestDeduplication(t *testing.T) {
	s := binary.New()

	data := make([]byte, 2048)
	for i := range data {
		data[i] = 0xDD
	}

	// Embed AES S-box
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

	// Embed AES Inverse S-box at a different offset
	aesInvSbox := []byte{
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
		0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
		0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
		0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
		0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	}
	copy(data[1000:], aesInvSbox)

	findings, err := s.ScanFile("dedup.so", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should only have ONE AES block-cipher finding (de-duplicated)
	aesCount := 0
	for _, f := range findings {
		if f.Properties.AlgorithmFamily == "aes" && f.Properties.Primitive == "block-cipher" {
			aesCount++
		}
	}
	if aesCount != 1 {
		t.Errorf("expected exactly 1 AES finding (de-duplicated), got %d", aesCount)
	}
}

// ---------------------------------------------------------------------------
// Finding fields validation
// ---------------------------------------------------------------------------

func TestFindingFields(t *testing.T) {
	s := binary.New()

	data := make([]byte, 256)
	for i := range data {
		data[i] = 0x00
	}

	rsaOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01}
	copy(data[50:], rsaOID)

	findings, err := s.ScanFile("check.exe", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := findings[0]

	if f.ID == "" {
		t.Error("finding ID should not be empty")
	}
	if f.AssetType != types.AssetAlgorithm {
		t.Errorf("expected AssetType %q, got %q", types.AssetAlgorithm, f.AssetType)
	}
	if f.Location.File != "check.exe" {
		t.Errorf("expected Location.File %q, got %q", "check.exe", f.Location.File)
	}
	if f.RuleID == "" {
		t.Error("RuleID should not be empty")
	}
	if f.Pass != 1 {
		t.Errorf("expected Pass=1, got %d", f.Pass)
	}
	if f.Description == "" {
		t.Error("Description should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Ed25519 OID detection
// ---------------------------------------------------------------------------

func TestDetectsEd25519OID(t *testing.T) {
	s := binary.New()

	data := make([]byte, 256)
	for i := range data {
		data[i] = 0xEE
	}

	ed25519OID := []byte{0x2b, 0x65, 0x70}
	copy(data[100:], ed25519OID)

	findings, err := s.ScanFile("test.dylib", data)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	assertFindingExists(t, findings, func(f types.Finding) bool {
		return f.Properties.AlgorithmFamily == "ed25519" &&
			f.Properties.QuantumStatus == types.QuantumVulnerable
	}, "Ed25519 OID detection with QuantumVulnerable status")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertFindingExists(t *testing.T, findings []types.Finding, match func(types.Finding) bool, description string) {
	t.Helper()
	for _, f := range findings {
		if match(f) {
			return
		}
	}
	t.Errorf("expected to find: %s", description)
	t.Logf("findings were:")
	for _, f := range findings {
		t.Logf("  - ID=%s Name=%q RuleID=%s Severity=%s Family=%s Primitive=%s QS=%s",
			f.ID, f.Name, f.RuleID, f.Severity,
			f.Properties.AlgorithmFamily, f.Properties.Primitive,
			f.Properties.QuantumStatus)
	}
}
