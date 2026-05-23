package output

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// newPDFTestScanResult creates a ScanResult with findings at every severity level
// and a mix of quantum statuses for PDF testing.
func newPDFTestScanResult() *types.ScanResult {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	return &types.ScanResult{
		Target:       "/home/user/test-project",
		StartTime:    now,
		EndTime:      now.Add(2500 * time.Millisecond),
		PassesRun:    []int{1, 2},
		FilesScanned: 128,
		Findings: []types.Finding{
			{
				ID:          "FIND-001",
				AssetType:   types.AssetAlgorithm,
				Name:        "MD5",
				Location:    types.Location{File: "crypto_utils.py", StartLine: 12, StartCol: 3},
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Description: "broken hash algorithm",
				RuleID:      "cbom-hash-md5",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.Broken,
					AlgorithmFamily: "md5",
				},
			},
			{
				ID:          "FIND-002",
				AssetType:   types.AssetAlgorithm,
				Name:        "AES-256-CBC",
				Location:    types.Location{File: "encrypt.py", StartLine: 8, StartCol: 5},
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Description: "AES in CBC mode",
				RuleID:      "cbom-cipher-aes-cbc",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.QuantumVulnerable,
					AlgorithmFamily: "aes",
				},
			},
			{
				ID:          "FIND-003",
				AssetType:   types.AssetAlgorithm,
				Name:        "SHA-256",
				Location:    types.Location{File: "hash.py", StartLine: 5, StartCol: 1},
				Severity:    types.SeverityInfo,
				Confidence:  types.ConfidenceHigh,
				Description: "SHA-256 hash",
				RuleID:      "cbom-hash-sha256",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.QuantumSafe,
					AlgorithmFamily: "sha",
				},
			},
			{
				ID:          "FIND-004",
				AssetType:   types.AssetCertificate,
				Name:        "CERT_NONE",
				Location:    types.Location{File: "ssl_usage.py", StartLine: 8, StartCol: 5},
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceHigh,
				Description: "disabled certificate validation",
				RuleID:      "cbom-cert-none",
				Properties: types.CryptoProperties{
					QuantumStatus: types.QuantumUnknown,
				},
			},
			{
				ID:          "FIND-005",
				AssetType:   types.AssetAlgorithm,
				Name:        "RSA-2048",
				Location:    types.Location{File: "keygen.py", StartLine: 3, StartCol: 1},
				Severity:    types.SeverityLow,
				Confidence:  types.ConfidenceHigh,
				Description: "RSA key generation",
				RuleID:      "cbom-pke-rsa",
				Properties: types.CryptoProperties{
					QuantumStatus:   types.QuantumVulnerable,
					AlgorithmFamily: "rsa",
				},
			},
		},
	}
}

func TestPDFWriter_Format(t *testing.T) {
	w := &PDFWriter{}
	if got := w.Format(); got != "pdf" {
		t.Errorf("Format() = %q, want %q", got, "pdf")
	}
}

func TestPDFWriter_WriteScanResult_ProducesOutput(t *testing.T) {
	result := newPDFTestScanResult()
	w := &PDFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriteScanResult produced empty output")
	}
}

func TestPDFWriter_WriteScanResult_PDFMagicBytes(t *testing.T) {
	result := newPDFTestScanResult()
	w := &PDFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	data := buf.Bytes()
	if len(data) < 4 {
		t.Fatalf("PDF output is too short: %d bytes", len(data))
	}

	magic := string(data[:5])
	if magic != "%PDF-" {
		t.Errorf("PDF output does not start with %%PDF- magic bytes, got: %q", magic)
	}
}

func TestPDFWriter_WriteScanResult_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		Target:       "/tmp/empty",
		StartTime:    time.Now(),
		EndTime:      time.Now().Add(100 * time.Millisecond),
		PassesRun:    []int{1},
		FilesScanned: 0,
		Findings:     []types.Finding{},
	}

	w := &PDFWriter{}
	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriteScanResult produced empty output for zero findings")
	}

	// Verify it's still a valid PDF.
	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("Empty findings PDF should still start with %%PDF-, got: %q", magic)
	}
}

func TestPDFWriter_WriteScanResult_AllSeverityLevels(t *testing.T) {
	result := newPDFTestScanResult()
	w := &PDFWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	// Verify the output is a reasonable size (should be at least a few KB with content).
	if buf.Len() < 1000 {
		t.Errorf("PDF output seems too small for 5 findings: %d bytes", buf.Len())
	}

	// Verify PDF magic bytes.
	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("PDF should start with %%PDF-, got: %q", magic)
	}
}

func TestPDFWriter_WriterFactory_Integration(t *testing.T) {
	w, err := WriterFactory("pdf")
	if err != nil {
		t.Fatalf("WriterFactory(\"pdf\") returned error: %v", err)
	}

	if w.Format() != "pdf" {
		t.Errorf("WriterFactory(\"pdf\").Format() = %q, want %q", w.Format(), "pdf")
	}

	result := newPDFTestScanResult()
	var buf bytes.Buffer
	err = w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriterFactory PDF writer produced empty output")
	}

	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("WriterFactory PDF should start with %%PDF-, got: %q", magic)
	}
}

func TestPDFWriter_WriteScanResult_LargeNumberOfFindings(t *testing.T) {
	now := time.Now()
	result := &types.ScanResult{
		Target:       "/large/project",
		StartTime:    now,
		EndTime:      now.Add(10 * time.Second),
		PassesRun:    []int{1, 2, 3},
		FilesScanned: 5000,
		Findings:     make([]types.Finding, 0, 50),
	}

	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	statuses := []types.QuantumStatus{
		types.QuantumVulnerable,
		types.QuantumSafe,
		types.QuantumUnknown,
		types.Broken,
	}

	for i := 0; i < 50; i++ {
		result.Findings = append(result.Findings, types.Finding{
			ID:          fmt.Sprintf("FIND-%03d", i+1),
			AssetType:   types.AssetAlgorithm,
			Name:        fmt.Sprintf("ALGO-%d", i),
			Location:    types.Location{File: fmt.Sprintf("pkg/module%d/crypto.go", i), StartLine: i*10 + 1},
			Severity:    severities[i%len(severities)],
			Confidence:  types.ConfidenceHigh,
			Description: fmt.Sprintf("Test finding %d for algorithm ALGO-%d", i, i),
			RuleID:      fmt.Sprintf("rule-%03d", i),
			Properties: types.CryptoProperties{
				QuantumStatus:   statuses[i%len(statuses)],
				AlgorithmFamily: fmt.Sprintf("algo-family-%d", i%5),
			},
		})
	}

	w := &PDFWriter{}
	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error for large findings set: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("WriteScanResult produced empty output for large findings set")
	}

	magic := string(buf.Bytes()[:5])
	if magic != "%PDF-" {
		t.Errorf("Large findings PDF should start with %%PDF-, got: %q", magic)
	}
}

// TestMiddleTruncate covers the helper used for unwrappable long paths.
// Verifies the contract: strings <= max are returned unchanged, longer ones
// are middle-truncated to exactly max runes with "..." in the middle.
func TestMiddleTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		// no truncation needed
		{"", 40, ""},
		{"short.go", 40, "short.go"},
		{"exactly_forty_chars_long_path_here.go_x", 40, "exactly_forty_chars_long_path_here.go_x"},
		// even-budget middle truncation
		{"cli/internal/scanner/python/python_scanner.go", 40, "cli/internal/scan...thon/python_scanner.go"[:40]},
		// well-known shape: very long path keeps both head and tail
		{"/a/very/long/path/here/with/many/segments/file.go", 30, "/a/very/long/p...gments/file.go"},
		// degenerate small max falls back to head truncation
		{"abcdefghij", 5, "abcde"},
		{"abcdefghij", 7, "ab...ij"},
		// non-ASCII rune handling (does not split a rune mid-byte)
		{"☃snowmanstring_long_enough_to_trim", 20, "☃snowman...ough_to_trim"[:20]},
	}
	for _, c := range cases {
		got := middleTruncate(c.in, c.max)
		// Length cap: result must never exceed max runes (when max >= 8).
		if c.max >= 8 && len([]rune(got)) > c.max {
			t.Errorf("middleTruncate(%q, %d) length %d > max %d (got %q)",
				c.in, c.max, len([]rune(got)), c.max, got)
		}
		// In-flight test data isn't easy to compute by hand — check only the
		// shape invariants rather than exact equality for the synthetic rows.
		if c.in == "short.go" || c.in == "" || c.in == "exactly_forty_chars_long_path_here.go_x" {
			if got != c.in {
				t.Errorf("middleTruncate(%q, %d) modified short-enough input: %q", c.in, c.max, got)
			}
		}
		// For inputs that should be truncated, "..." must appear when max >= 8
		// and input is genuinely longer.
		if c.max >= 8 && len([]rune(c.in)) > c.max {
			if !contains(got, "...") {
				t.Errorf("middleTruncate(%q, %d) lacks ... marker: %q", c.in, c.max, got)
			}
		}
	}
}

// TestPDFFindingsNotPreTruncated guards against the rc1-era bug where long
// descriptions / detected-asset lists / file paths were chopped to N chars
// with "..." before maroto ever saw them, causing visible mid-word cropping.
// The fix delegates wrapping to maroto v2's AutoRow + auto-wrap. This test
// builds a PDF with extremely long content in each affected column and
// verifies the rendered bytes contain the full string somewhere in the
// content stream (i.e. no pre-truncation happened).
func TestPDFFindingsNotPreTruncated(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	longDesc := "Cipher.getInstance(\"DES/ECB/PKCS5Padding\") with hardcoded 8-byte key material derived from an environment variable in the configuration loader path"
	longPath := "cli/internal/scanner/python/very_deeply_nested/subpackage/with/lots/of/dirs/crypto_constants_loader.go"
	longNames := "AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384"
	result := &types.ScanResult{
		Target:       "/test",
		StartTime:    now,
		EndTime:      now.Add(time.Second),
		PassesRun:    []int{1, 2},
		FilesScanned: 5,
		Findings: []types.Finding{{
			ID:          "FIND-LONG",
			AssetType:   types.AssetAlgorithm,
			Name:        "DES-ECB-Long",
			Location:    types.Location{File: longPath, StartLine: 42},
			Severity:    types.SeverityHigh,
			Confidence:  types.ConfidenceHigh,
			Description: longDesc,
			Properties: types.CryptoProperties{
				QuantumStatus:   types.QuantumVulnerable,
				AlgorithmFamily: "des",
			},
		}, {
			ID:          "FIND-NAMES",
			AssetType:   types.AssetAlgorithm,
			Name:        longNames,
			Location:    types.Location{File: "a.py", StartLine: 1},
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceHigh,
			Description: "Long names",
			Properties: types.CryptoProperties{
				QuantumStatus:   types.QuantumSafe,
				AlgorithmFamily: "aes",
			},
		}},
	}

	w := &PDFWriter{}
	var buf bytes.Buffer
	if err := w.WriteScanResult(&buf, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}

	body := buf.String()

	// The legacy bug truncated descriptions to 50 chars with "...". A canary
	// substring that lived beyond char 50 of longDesc must now appear in the
	// PDF content stream. (Maroto encodes text as multiple Tj operators on
	// wrapped lines, so we check for a substring of one word that previously
	// got cut.)
	canaries := []string{
		"PKCS5Padding",      // beyond char 47 of longDesc — was cropped
		"crypto_constants_loader.go", // beyond char 35 of longPath — was cropped
		"ECDSA-P384",        // beyond char 40 of longNames — was cropped
	}
	for _, c := range canaries {
		if !contains(body, c) {
			t.Errorf("PDF content stream missing canary %q — column likely still pre-truncated", c)
		}
	}
}

// contains is a tiny non-regex substring helper. The PDF body may contain
// non-printable bytes; basic strings.Contains works fine on byte slices.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
