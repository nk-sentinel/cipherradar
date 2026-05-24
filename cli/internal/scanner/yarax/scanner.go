package yarax

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	logpkg "github.com/nk-sentinel/cipherradar/cli/pkg/log"
)

// YaraXScanner implements scanner.Scanner by delegating to a YARA-X
// subprocess (`yr`). It targets binary and archive files (.so, .dll,
// .dylib, .exe, .class, .jar, .whl, .a, .o, .wasm) so that the YARA-X
// ruleset (lands in Sub-PR B) can detect crypto assets in compiled
// outputs alongside the existing native binary / JAR / wheel scanners.
//
// Registration model: registered as a Universal in scannerinit/defaults
// rather than via Registry.Register so it doesn't displace the existing
// binary/jar/wheel extension claims (Registry.ForExtension is last-write-
// wins). The Universal dispatch in walker.go (today) only fires on files
// WITHOUT a language scanner, which means YARA-X currently sees no .so
// files — Sub-PR C extends walker.go's dispatch to also invoke Pass-3
// universals on language-matched files, completing the "binary scanner
// and YARA-X both fire on the same file" model that ADR-039 specifies.
//
// For Sub-PR A this still means the scanner soft-skips on every file
// (no rules yet, runner often absent), and the registration just
// reserves the seam without changing observable behavior.
type YaraXScanner struct {
	runner    *Runner
	rulesDir  string
	exts      map[string]struct{}
	extsOrder []string
}

// supportedExtensions enumerates the file extensions YARA-X handles. The
// list is declared once so both Extensions() and the internal ScanFile
// dispatch filter stay in lock-step.
var supportedExtensions = []string{
	".so", ".dll", ".dylib", ".exe", ".class",
	".jar", ".whl",
	".a", ".o",
	".wasm",
}

// New builds a YaraXScanner using the standard discovery path
// (NewRunner + RulesDir env lookup). When `yr` is absent, runner is
// nil and ScanFile soft-skips per the package contract. When the rules
// directory is unset, the same soft-skip applies — Sub-PR A ships
// without any rules, so this is the expected runtime state until Sub-PR
// B lands. The constructor is intentionally cheap and always returns a
// non-nil scanner so the registry doesn't need conditional registration.
func New() *YaraXScanner {
	return newScanner(NewRunner(), RulesDir())
}

// NewWithRunner constructs a YaraXScanner with an explicit runner and
// rules directory. Exported for tests so they can pin both knobs
// without touching env vars or relying on host installation.
func NewWithRunner(r *Runner, rulesDir string) *YaraXScanner {
	return newScanner(r, rulesDir)
}

func newScanner(r *Runner, rulesDir string) *YaraXScanner {
	extsOrder := append([]string(nil), supportedExtensions...)
	extSet := make(map[string]struct{}, len(extsOrder))
	for _, e := range extsOrder {
		extSet[e] = struct{}{}
	}
	return &YaraXScanner{
		runner:    r,
		rulesDir:  rulesDir,
		exts:      extSet,
		extsOrder: extsOrder,
	}
}

// Name returns the scanner's identifier surfaced in --debug logs and
// scanner_start / scanner_complete events.
func (s *YaraXScanner) Name() string { return "yarax" }

// Extensions returns the file extensions this scanner handles. The set
// matches ADR-039: native binary formats + JVM class files + JVM/Python
// archives + low-level object files + WASM modules. The list is
// declarative — because the scanner is registered as a Universal, the
// walker dispatches every file to ScanFile and the internal extension
// gate (handlesPath) decides whether to invoke YARA-X.
func (s *YaraXScanner) Extensions() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.extsOrder))
	copy(out, s.extsOrder)
	return out
}

// handlesPath reports whether the given file path is eligible for
// YARA-X scanning. Two cases qualify:
//
//  1. The extension is in the declared supported set
//     (.so, .dll, .dylib, .exe, .class, .jar, .whl, .a, .o, .wasm).
//  2. The file has no extension at all. Unix executables and many
//     test fixtures (including the ones under
//     CipherRadarTestProj/binaries/dist/) have no extension; gating
//     strictly on extension would silently exclude them. YARA-X is
//     cheap to invoke on a single file, and the soft-skip path
//     dominates until Sub-PR B ships rules, so the false-positive
//     cost of admitting extensionless files is small.
//
// Source files with known language extensions (.go, .py, .js, ...)
// are excluded — those are handled by language scanners, and walker.go
// already routes universals only to files without a language scanner,
// but this gate provides defense in depth in case the walker dispatch
// model changes later.
func (s *YaraXScanner) handlesPath(path string) bool {
	if s == nil {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return true
	}
	_, ok := s.exts[ext]
	return ok
}

// ScanFile dispatches a single file through the YARA-X runner. Soft-
// skips when:
//   - the extension is outside the YARA-X target set (Universal
//     registration means walker.go hands us every file, including
//     source files we don't care about);
//   - the runner is unavailable (yr not installed);
//   - the rules dir is empty (Sub-PR A's no-rules state).
//
// `path` is the relative scan-root path the walker hands us; `content`
// is the file bytes. Walker doesn't expose the absolute on-disk path,
// so when the relative path doesn't resolve from the cradar process
// CWD we fall back to staging the bytes in a tempfile and pointing
// yr at that. This keeps the scanner correct regardless of where
// cradar is invoked from. The optimisation that lifts the absolute
// path from the walker (avoiding the tempfile copy) is Sub-PR C scope.
//
// Findings returned from ParseResults are run through
// scanner.AnnotateFindings so they pick up consistent Category /
// Maturity defaults — without it, Pass-3 findings would be silently
// dropped by the --only-inventory / --only-security filters.
func (s *YaraXScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if s == nil {
		return nil, nil
	}
	if !s.handlesPath(path) {
		return nil, nil
	}
	if s.runner == nil || !s.runner.Available() {
		return nil, nil
	}
	if s.rulesDir == "" {
		return nil, nil
	}
	logpkg.Get().YaraXScanFire(path)

	scanPath, cleanup, err := materializeForScan(path, content)
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	findings, err := s.runner.Scan(scanPath, s.rulesDir)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return nil, nil
	}
	// Rewrite any tempfile path that leaked into a finding back to the
	// caller-visible scan-relative path so output is stable and
	// matches what the walker sorts by.
	for i := range findings {
		if scanPath != path && findings[i].Location.File == scanPath {
			findings[i].Location.File = path
		}
	}
	return scanner.AnnotateFindings(findings), nil
}

// materializeForScan resolves a path that yr can open. When the
// relative path resolves to a readable file from the cradar process
// CWD (e.g. user ran `cradar scan ./binaries/` from the repo root),
// we hand yr that path directly. Otherwise we stage the in-memory
// content in a tempfile and hand yr the tempfile path. cleanup is
// non-nil only when a tempfile was created.
func materializeForScan(path string, content []byte) (string, func(), error) {
	if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Size() == int64(len(content)) {
		// Path is openable as-is and the size matches the in-memory
		// content; this is the common case when cradar is run from
		// the scan root.
		return path, nil, nil
	}

	tmp, err := os.CreateTemp("", "yarax-scan-*"+filepath.Ext(path))
	if err != nil {
		return "", nil, fmt.Errorf("yarax: stage tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", nil, fmt.Errorf("yarax: write tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", nil, fmt.Errorf("yarax: close tempfile: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmpPath) }
	return tmpPath, cleanup, nil
}
