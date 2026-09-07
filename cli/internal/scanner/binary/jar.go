package binary

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/keystore"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Archive-scanning bomb guards. A crafted archive (or deeply nested one) must
// not exhaust memory or CPU. All limits apply across the whole nesting tree of
// one top-level archive via a shared archiveBudget.
const (
	maxArchiveDepth      = 4                 // jar-in-war-in-jar... nesting cap
	maxArchiveTotalBytes = 512 * 1024 * 1024 // total uncompressed budget (512 MB)
	maxArchiveEntries    = 20000             // total entry-count cap
	maxArchiveEntryBytes = 50 * 1024 * 1024  // per-entry cap (50 MB)
)

// recursableArchiveExts are nested-archive types the scanner recurses into.
var recursableArchiveExts = map[string]bool{
	".jar": true, ".war": true, ".ear": true, ".zip": true,
}

// keystoreEntryExtensions are routed to the keystore scanner when found inside
// an archive (e.g. a JKS/PKCS12 bundled in a JAR).
var keystoreEntryExtensions = map[string]bool{
	".jks": true, ".keystore": true, ".truststore": true,
	".p12": true, ".pfx": true, ".pkcs12": true, ".pk12": true,
	".jceks": true, ".bks": true,
}

// archiveBudget bounds a single top-level archive scan across all nesting
// levels to defend against decompression bombs. truncated is set when any
// limit was hit so the caller can flag partial coverage.
type archiveBudget struct {
	bytesLeft   int64
	entriesLeft int
	truncated   bool
}

// JARScanner handles JAR, WAR, and EAR files by extracting their contents
// and scanning with byte-pattern matching and (optionally) the Java source
// scanner via CFR decompilation.
type JARScanner struct {
	javaScanner     scanner.Scanner
	configScanner   scanner.Scanner
	keystoreScanner scanner.Scanner
	// maxDepth caps nested-archive recursion (jar-in-jar). 0 means top-level
	// only (no recursion into nested archives); the built-in default is
	// maxArchiveDepth.
	maxDepth int
}

// NewJARScanner creates a new JAR/WAR/EAR/ZIP scanner with the built-in default
// nesting-depth cap (maxArchiveDepth).
func NewJARScanner() *JARScanner {
	return NewJARScannerWithDepth(maxArchiveDepth)
}

// NewJARScannerWithDepth creates a JAR/WAR/EAR/ZIP scanner with an explicit
// nested-archive recursion cap. A negative depth falls back to the built-in
// default; 0 disables recursion into nested archives (top-level still scanned).
func NewJARScannerWithDepth(depth int) *JARScanner {
	if depth < 0 {
		depth = maxArchiveDepth
	}
	return &JARScanner{
		javaScanner:     java.New(),
		configScanner:   config.New(),
		keystoreScanner: keystore.New(),
		maxDepth:        depth,
	}
}

// Name returns the scanner name.
func (s *JARScanner) Name() string {
	return "jar"
}

// Extensions returns the archive extensions this scanner handles.
func (s *JARScanner) Extensions() []string {
	return []string{".jar", ".war", ".ear", ".zip"}
}

// ScanFile scans a JAR/WAR/EAR/ZIP archive: it recurses into nested archives
// (bounded), routes entries to the appropriate sub-scanner (crypto constants in
// .class, config files, keystores), and defends against decompression bombs via
// a shared budget (depth + total-uncompressed + entry-count + per-entry
// LimitReader).
func (s *JARScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	budget := &archiveBudget{bytesLeft: maxArchiveTotalBytes, entriesLeft: maxArchiveEntries}
	findings, err := s.scanArchive(path, content, 0, budget)
	if err != nil {
		return nil, err
	}

	// Optional: try CFR decompilation of the top-level archive if available.
	findings = append(findings, s.tryCFRDecompile(path, content)...)

	if budget.truncated {
		findings = append(findings, partialArchiveFinding(path))
	}
	return scanner.AnnotateFindings(findings), nil
}

// scanArchive recursively scans one archive's entries within the shared budget.
func (s *JARScanner) scanArchive(path string, content []byte, depth int, budget *archiveBudget) ([]types.Finding, error) {
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		if depth == 0 {
			return nil, fmt.Errorf("failed to open archive %s: %w", path, err)
		}
		return nil, nil // a corrupt nested archive is skipped, not fatal
	}

	var findings []types.Finding
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if budget.entriesLeft <= 0 || budget.bytesLeft <= 0 {
			budget.truncated = true
			break
		}
		budget.entriesLeft--

		ext := strings.ToLower(filepath.Ext(f.Name))
		entryPath := fmt.Sprintf("%s!/%s", path, f.Name)

		entryContent, n, rerr := readZipEntryLimited(f, budget.bytesLeft)
		if rerr != nil {
			if rerr == errEntryTooLarge {
				budget.truncated = true
			}
			continue
		}
		budget.bytesLeft -= n

		switch {
		case recursableArchiveExts[ext]:
			if depth+1 > s.maxDepth {
				budget.truncated = true
				continue
			}
			nested, _ := s.scanArchive(entryPath, entryContent, depth+1, budget)
			findings = append(findings, nested...)

		case ext == ".class":
			findings = append(findings, scanBytes(entryPath, entryContent)...)

		case ext == ".properties", ext == ".env":
			if cf, cerr := s.configScanner.ScanFile(entryPath, entryContent); cerr == nil {
				findings = append(findings, cf...)
			}

		case ext == ".xml", ext == ".yml", ext == ".yaml":
			findings = append(findings, scanConfigContent(entryPath, entryContent)...)

		case keystoreEntryExtensions[ext]:
			if kf, kerr := s.keystoreScanner.ScanFile(entryPath, entryContent); kerr == nil {
				findings = append(findings, kf...)
			}
		}
	}
	return findings, nil
}

// errEntryTooLarge signals an entry that exceeds the per-entry cap (possible
// decompression bomb) — the caller skips it and flags the archive as partial.
var errEntryTooLarge = fmt.Errorf("archive entry exceeds size cap")

// readZipEntryLimited reads a ZIP entry without trusting its declared size: it
// bounds the read with an io.LimitReader at min(per-entry cap, remaining
// budget), so a bomb entry that lies about UncompressedSize64 cannot exhaust
// memory. Returns the content and the number of bytes actually read.
func readZipEntryLimited(f *zip.File, budgetBytes int64) ([]byte, int64, error) {
	limit := int64(maxArchiveEntryBytes)
	if budgetBytes < limit {
		limit = budgetBytes
	}
	if limit <= 0 {
		return nil, 0, errEntryTooLarge
	}

	rc, err := f.Open()
	if err != nil {
		return nil, 0, err
	}
	defer rc.Close()

	// Read at most cap+1 so we can detect (and reject) an over-cap entry
	// without materializing the whole bomb.
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) > limit {
		return nil, 0, errEntryTooLarge
	}
	return data, int64(len(data)), nil
}

// partialArchiveFinding notes that an archive was only partially scanned
// because a bomb guard (depth / size / entry-count) was hit.
func partialArchiveFinding(path string) types.Finding {
	return types.Finding{
		ID:          nextFindingID(),
		AssetType:   types.AssetRelatedCryptoMaterial,
		Name:        "Archive partially scanned",
		Location:    binaryLocation(path, 0, "archive"),
		Severity:    types.SeverityLow,
		Confidence:  types.ConfidenceLow,
		Description: "Archive scanning stopped at a safety limit (depth/size/entry-count); some nested content was not inspected",
		RuleID:      "cbom-archive-partial",
		Pass:        1,
	}
}

// scanConfigContent scans XML/YAML config content for crypto-related strings
// embedded as byte sequences (algorithm names, TLS versions).
func scanConfigContent(path string, content []byte) []types.Finding {
	var findings []types.Finding

	// Search for common crypto algorithm string patterns in config files
	type configPattern struct {
		needle   []byte
		name     string
		family   string
		severity types.Severity
	}

	patterns := []configPattern{
		{[]byte("TLSv1.0"), "TLSv1.0", "tls", types.SeverityHigh},
		{[]byte("TLSv1.1"), "TLSv1.1", "tls", types.SeverityHigh},
		{[]byte("SSLv3"), "SSLv3", "tls", types.SeverityHigh},
		{[]byte("DES"), "DES", "des", types.SeverityHigh},
		{[]byte("RC4"), "RC4", "rc4", types.SeverityHigh},
		{[]byte("MD5"), "MD5", "md5", types.SeverityHigh},
	}

	for _, p := range patterns {
		if bytes.Contains(content, p.needle) {
			findings = append(findings, types.Finding{
				ID:        nextFindingID(),
				AssetType: types.AssetAlgorithm,
				Name:      p.name,
				Location: types.Location{
					File:    path,
					Snippet: fmt.Sprintf("[config] %s reference in %s", p.name, filepath.Base(path)),
				},
				Severity:   p.severity,
				Confidence: types.ConfidenceLow,
				Properties: types.CryptoProperties{
					AlgorithmFamily: p.family,
				},
				Description: fmt.Sprintf("Crypto reference %q found in config file inside archive", p.name),
				RuleID:      fmt.Sprintf("cbom-binary-jar-config-%s", strings.ToLower(p.family)),
				Pass:        1,
			})
		}
	}

	return findings
}

// cfrJarPath returns the path to the CFR decompiler JAR, or empty string if
// not found. Checks ~/.cradar/tools/cfr.jar per ADR-026.
func cfrJarPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".cradar", "tools", "cfr.jar")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// tryCFRDecompile attempts to decompile the JAR using CFR and scan the
// resulting Java source. Returns nil findings if CFR is not available.
func (s *JARScanner) tryCFRDecompile(jarPath string, _ []byte) []types.Finding {
	cfr := cfrJarPath()
	if cfr == "" {
		return nil
	}

	// Check that java is available
	javaCmd, err := exec.LookPath("java")
	if err != nil {
		return nil
	}

	// Create temp directory for decompiled output
	tmpDir, err := os.MkdirTemp("", "cbom-cfr-*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmpDir)

	// Run CFR: java -jar cfr.jar <jar> --outputdir <tmpDir>
	cmd := exec.Command(javaCmd, "-jar", cfr, jarPath, "--outputdir", tmpDir)
	if err := cmd.Run(); err != nil {
		return nil
	}

	// Walk decompiled .java files and scan with Java scanner
	var findings []types.Finding
	_ = filepath.WalkDir(tmpDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".java" {
			return nil
		}

		content, err := os.ReadFile(path) // #nosec G122 -- WalkDir over the CFR-decompiled output in a temp dir cradar just created and solely owns; no external writer, so no TOCTOU exposure
		if err != nil {
			return nil
		}

		// Build a relative path that indicates the origin
		relPath, _ := filepath.Rel(tmpDir, path)
		entryPath := fmt.Sprintf("%s!/%s", jarPath, relPath)

		javaFindings, err := s.javaScanner.ScanFile(entryPath, content)
		if err == nil {
			findings = append(findings, javaFindings...)
		}
		return nil
	})

	return findings
}
