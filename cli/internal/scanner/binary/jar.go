package binary

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// JARScanner handles JAR, WAR, and EAR files by extracting their contents
// and scanning with byte-pattern matching and (optionally) the Java source
// scanner via CFR decompilation.
type JARScanner struct {
	javaScanner   scanner.Scanner
	configScanner scanner.Scanner
}

// NewJARScanner creates a new JAR/WAR/EAR scanner.
func NewJARScanner() *JARScanner {
	return &JARScanner{
		javaScanner:   java.New(),
		configScanner: config.New(),
	}
}

// Name returns the scanner name.
func (s *JARScanner) Name() string {
	return "jar"
}

// Extensions returns the archive extensions this scanner handles.
func (s *JARScanner) Extensions() []string {
	return []string{".jar", ".war", ".ear"}
}

// ScanFile scans a JAR/WAR/EAR file by opening it as a ZIP archive,
// extracting relevant files, and running appropriate sub-scanners.
func (s *JARScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("failed to open JAR %s: %w", path, err)
	}

	var findings []types.Finding

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(f.Name))
		entryPath := fmt.Sprintf("%s!/%s", path, f.Name)

		entryContent, err := readZipEntry(f)
		if err != nil {
			continue // skip unreadable entries
		}

		switch ext {
		case ".class":
			// Scan raw .class bytes for crypto constants
			classFindings := scanBytes(entryPath, entryContent)
			findings = append(findings, classFindings...)

		case ".properties", ".env":
			// Scan config files with the config scanner
			configFindings, err := s.configScanner.ScanFile(entryPath, entryContent)
			if err == nil {
				findings = append(findings, configFindings...)
			}

		case ".xml", ".yml", ".yaml":
			// Scan for crypto references in config files using byte patterns
			// that indicate TLS/SSL or algorithm configuration.
			xmlFindings := scanConfigContent(entryPath, entryContent)
			findings = append(findings, xmlFindings...)
		}
	}

	// Optional: try CFR decompilation if available
	cfrFindings := s.tryCFRDecompile(path, content)
	findings = append(findings, cfrFindings...)

	return findings, nil
}

// readZipEntry reads the full content of a ZIP entry.
func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// Cap at 50 MB to avoid memory exhaustion on large entries.
	const maxSize = 50 * 1024 * 1024
	if f.UncompressedSize64 > maxSize {
		return nil, fmt.Errorf("entry too large: %d bytes", f.UncompressedSize64)
	}

	var buf bytes.Buffer
	buf.Grow(int(f.UncompressedSize64))
	if _, err := buf.ReadFrom(rc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

		content, err := os.ReadFile(path)
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
