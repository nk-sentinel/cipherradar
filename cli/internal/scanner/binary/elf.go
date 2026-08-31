package binary

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// nativeBinaryExtensions lists file extensions handled by the ELFScanner.
var nativeBinaryExtensions = map[string]bool{
	".so":    true,
	".dll":   true,
	".dylib": true,
	".exe":   true,
}

// ELFScanner detects cryptographic constants in native binaries (.so, .dll,
// .dylib, .exe). For ELF files it parses section headers to focus scanning
// on data sections (.rodata, .data) for efficiency. For Go binaries it
// extracts go.buildinfo to identify the Go version and imported crypto
// packages.
type ELFScanner struct{}

// NewELFScanner creates a new ELFScanner instance.
func NewELFScanner() *ELFScanner {
	return &ELFScanner{}
}

// Name returns the scanner's name.
func (s *ELFScanner) Name() string {
	return "elf"
}

// Extensions returns the file extensions this scanner handles.
func (s *ELFScanner) Extensions() []string {
	return []string{".so", ".dll", ".dylib", ".exe"}
}

// ScanFile scans a native binary file. For ELF files it targets data sections;
// for non-ELF files it falls back to full-content byte-pattern scanning.
func (s *ELFScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	var findings []types.Finding

	// Try ELF-specific parsing first.
	elfFindings, isELF := s.scanELF(path, content)
	if isELF {
		findings = append(findings, elfFindings...)
	} else {
		// Non-ELF native binary: scan raw bytes with crypto patterns.
		findings = append(findings, scanBytes(path, content)...)

		// Also check for Go build info in non-ELF binaries (e.g. PE, Mach-O).
		goFindings := s.extractGoBuildInfo(path, content)
		findings = append(findings, goFindings...)
	}

	// Version-string library fingerprinting runs on the full content for any
	// native binary (ELF or not) — the top rung of the detection ladder.
	findings = append(findings, scanLibraryVersions(path, content)...)

	return scanner.AnnotateFindings(findings), nil
}

// scanELF attempts to parse the content as an ELF binary. If successful, it
// scans data sections and extracts Go build info. Returns the findings and a
// bool indicating whether the file was valid ELF.
func (s *ELFScanner) scanELF(path string, content []byte) ([]types.Finding, bool) {
	f, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var findings []types.Finding

	// Scan data sections for crypto patterns.
	sectionFindings := s.scanELFSections(path, f)
	findings = append(findings, sectionFindings...)

	// Try to extract Go build info.
	goFindings := s.extractGoBuildInfo(path, content)
	findings = append(findings, goFindings...)

	return findings, true
}

// dataSections lists ELF section names that are worth scanning for
// cryptographic constants. These hold read-only data and initialized data.
var dataSections = []string{
	".rodata",
	".data",
	".data.rel.ro",
	".rdata",
	".noptrdata",
	".go.buildinfo",
}

// scanELFSections scans relevant ELF data sections for crypto byte patterns.
func (s *ELFScanner) scanELFSections(path string, f *elf.File) []types.Finding {
	var allData []byte
	scannedAny := false

	for _, name := range dataSections {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		allData = append(allData, data...)
		scannedAny = true
	}

	if !scannedAny {
		return nil
	}

	return scanBytes(path, allData)
}

// knownGoCryptoPackages maps Go standard-library crypto package import paths
// to their algorithm family and primitive type for CBOM classification.
var knownGoCryptoPackages = map[string]struct {
	Family    string
	Primitive string
	Name      string
}{
	"crypto/aes":                           {Family: "aes", Primitive: "block-cipher", Name: "AES (Go stdlib)"},
	"crypto/des":                           {Family: "des", Primitive: "block-cipher", Name: "DES (Go stdlib)"},
	"crypto/rc4":                           {Family: "rc4", Primitive: "stream-cipher", Name: "RC4 (Go stdlib)"},
	"crypto/md5":                           {Family: "md5", Primitive: "hash", Name: "MD5 (Go stdlib)"},
	"crypto/sha1":                          {Family: "sha1", Primitive: "hash", Name: "SHA-1 (Go stdlib)"},
	"crypto/sha256":                        {Family: "sha-256", Primitive: "hash", Name: "SHA-256 (Go stdlib)"},
	"crypto/sha512":                        {Family: "sha-512", Primitive: "hash", Name: "SHA-512 (Go stdlib)"},
	"crypto/rsa":                           {Family: "rsa", Primitive: "pke", Name: "RSA (Go stdlib)"},
	"crypto/ecdsa":                         {Family: "ecdsa", Primitive: "signature", Name: "ECDSA (Go stdlib)"},
	"crypto/ecdh":                          {Family: "ecdh", Primitive: "key-agree", Name: "ECDH (Go stdlib)"},
	"crypto/ed25519":                       {Family: "ed25519", Primitive: "signature", Name: "Ed25519 (Go stdlib)"},
	"crypto/tls":                           {Family: "tls", Primitive: "", Name: "TLS (Go stdlib)"},
	"golang.org/x/crypto/chacha20poly1305": {Family: "chacha20", Primitive: "ae", Name: "ChaCha20-Poly1305 (x/crypto)"},
	"golang.org/x/crypto/sha3":             {Family: "sha3-256", Primitive: "hash", Name: "SHA-3 (x/crypto)"},
	"golang.org/x/crypto/blake2b":          {Family: "blake2b", Primitive: "hash", Name: "BLAKE2b (x/crypto)"},
	"golang.org/x/crypto/blake2s":          {Family: "blake2s", Primitive: "hash", Name: "BLAKE2s (x/crypto)"},
}

// goBuildInfoMagic is the byte sequence identifying the Go buildinfo header
// embedded in Go binaries.
var goBuildInfoMagic = []byte("\xff Go buildinf:")

// extractGoBuildInfo searches for Go build information in the binary content.
// Go binaries embed a buildinfo header containing the Go version, module path,
// and dependency list. We scan the raw bytes for known crypto package paths
// rather than relying on debug/buildinfo which requires seekable io.ReaderAt
// with specific section layouts.
func (s *ELFScanner) extractGoBuildInfo(path string, content []byte) []types.Finding {
	// Quick check: is this a Go binary at all?
	if !bytes.Contains(content, goBuildInfoMagic) {
		return nil
	}

	var findings []types.Finding
	seen := make(map[string]bool)

	// Extract Go version if present. Go binaries contain "go1.XX.YY" strings.
	goVersion := extractGoVersion(content)

	for pkg, info := range knownGoCryptoPackages {
		if seen[info.Family+"|"+info.Primitive] {
			continue
		}
		// Search for the package path string in the binary.
		if bytes.Contains(content, []byte(pkg)) {
			seen[info.Family+"|"+info.Primitive] = true

			qi := quantum.GetInfo(info.Family)
			severity := patternSeverity(info.Family)

			desc := fmt.Sprintf("Go crypto package %q linked in binary", pkg)
			if goVersion != "" {
				desc = fmt.Sprintf("Go crypto package %q linked in binary (Go %s)", pkg, goVersion)
			}

			name := info.Name
			if info.Primitive == "" && info.Family == "tls" {
				// TLS is a protocol, not an algorithm.
				findings = append(findings, types.Finding{
					ID:         nextFindingID(),
					AssetType:  types.AssetProtocol,
					Name:       name,
					Location:   binaryLocation(path, 0, name),
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceMedium,
					Properties: types.CryptoProperties{
						ProtocolType: "tls",
					},
					Description: desc,
					RuleID:      "cbom-binary-go-tls",
					Pass:        1,
				})
				continue
			}

			findings = append(findings, types.Finding{
				ID:         nextFindingID(),
				AssetType:  types.AssetAlgorithm,
				Name:       name,
				Location:   binaryLocation(path, 0, name),
				Severity:   severity,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					Primitive:        info.Primitive,
					AlgorithmFamily:  info.Family,
					QuantumStatus:    qi.Status,
					NistQuantumLevel: qi.NistLevel,
				},
				Description: desc,
				RuleID:      fmt.Sprintf("cbom-binary-go-%s", info.Family),
				Pass:        1,
			})
		}
	}

	return findings
}

// extractGoVersion searches for the Go version string in binary content.
// Go embeds version strings like "go1.21.5" in the binary.
func extractGoVersion(content []byte) string {
	// Search for "go1." prefix which is the standard Go version format.
	prefix := []byte("go1.")
	idx := bytes.Index(content, prefix)
	if idx < 0 {
		return ""
	}

	// Extract the version string (up to 12 chars for "go1.XX.YY" patterns).
	end := idx + 12
	if end > len(content) {
		end = len(content)
	}

	version := content[idx:end]
	// Trim at the first non-version character.
	var result []byte
	for _, b := range version {
		if (b >= '0' && b <= '9') || b == '.' || (b >= 'a' && b <= 'z') {
			result = append(result, b)
		} else {
			break
		}
	}

	s := string(result)
	// Validate it looks like a version: must start with "go1." and have at
	// least one more digit.
	if len(s) < 5 || !strings.HasPrefix(s, "go1.") {
		return ""
	}
	return s
}
