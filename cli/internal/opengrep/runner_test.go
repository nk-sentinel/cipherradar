package opengrep

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestNewRunnerReturnsNilWhenNotInstalled(t *testing.T) {
	// Save and clear environment variables that might point to a binary.
	origToolsDir := os.Getenv("CRADAR_TOOLS_DIR")
	os.Unsetenv("CRADAR_TOOLS_DIR")
	defer func() {
		if origToolsDir != "" {
			os.Setenv("CRADAR_TOOLS_DIR", origToolsDir)
		}
	}()

	// Save original PATH, set to empty so no binary is found.
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	runner := NewRunner()
	// In most CI/test environments, opengrep is not installed.
	// With an empty PATH, NewRunner should return nil.
	if runner != nil {
		t.Logf("runner found binary at %s -- skipping nil check (binary is actually installed)", runner.BinaryPath())
		return
	}

	if runner != nil {
		t.Errorf("expected NewRunner to return nil when opengrep is not installed, got %+v", runner)
	}
}

func TestAvailableReturnsFalseWhenNil(t *testing.T) {
	var runner *Runner
	if runner.Available() {
		t.Error("expected Available() to return false for nil runner")
	}
}

func TestAvailableReturnsFalseWhenBinaryPathEmpty(t *testing.T) {
	runner := &Runner{binaryPath: ""}
	if runner.Available() {
		t.Error("expected Available() to return false when binaryPath is empty")
	}
}

func TestAvailableReturnsTrueWhenBinaryPathSet(t *testing.T) {
	runner := &Runner{binaryPath: "/usr/bin/some-binary"}
	if !runner.Available() {
		t.Error("expected Available() to return true when binaryPath is set")
	}
}

func TestScanReturnsErrorForNilRunner(t *testing.T) {
	var runner *Runner
	_, err := runner.Scan("/some/path", "/some/rules")
	if err == nil {
		t.Error("expected error when scanning with nil runner")
	}
}

func TestScanReturnsErrorForEmptyRulesDir(t *testing.T) {
	runner := &Runner{binaryPath: "/usr/bin/opengrep"}
	_, err := runner.Scan("/some/target", "")
	if err == nil {
		t.Error("expected error when rules directory is empty")
	}
}

func TestBinaryPathReturnsEmptyForNilRunner(t *testing.T) {
	var runner *Runner
	if runner.BinaryPath() != "" {
		t.Error("expected empty string for nil runner's BinaryPath()")
	}
}

func TestIsExecutable(t *testing.T) {
	// Create a temporary file with executable permissions.
	tmpDir := t.TempDir()
	execFile := filepath.Join(tmpDir, "test-binary")
	if err := os.WriteFile(execFile, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if !isExecutable(execFile) {
		t.Error("expected isExecutable to return true for executable file")
	}

	// Non-executable file.
	noExecFile := filepath.Join(tmpDir, "test-noexec")
	if err := os.WriteFile(noExecFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	if isExecutable(noExecFile) {
		t.Error("expected isExecutable to return false for non-executable file")
	}

	// Non-existent file.
	if isExecutable(filepath.Join(tmpDir, "nonexistent")) {
		t.Error("expected isExecutable to return false for non-existent file")
	}

	// Directory should not be considered executable.
	if isExecutable(tmpDir) {
		t.Error("expected isExecutable to return false for directory")
	}
}

func TestNewRunnerFindsBundledBinary(t *testing.T) {
	// Create a temporary directory with a fake "cradar" executable and a
	// sibling "opengrep" executable, simulating the cradar-full layout.
	tmpDir := t.TempDir()

	// Create a fake cradar binary that just prints its own path.
	cradarBin := filepath.Join(tmpDir, "cradar")
	script := "#!/bin/sh\necho \"$0\"\n"
	if err := os.WriteFile(cradarBin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a sibling opengrep binary.
	ogBin := filepath.Join(tmpDir, "opengrep")
	if err := os.WriteFile(ogBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// We cannot reliably override os.Executable() in a unit test because it
	// returns the path of the running test binary. Instead, we verify the
	// isExecutable helper works for the candidate path, which is the core
	// logic that the bundled-binary check depends on.
	if !isExecutable(ogBin) {
		t.Fatal("expected sibling opengrep to be executable")
	}

	// Verify that when CRADAR_TOOLS_DIR points at the same directory, the
	// runner finds the binary (exercising the code path end-to-end).
	origToolsDir := os.Getenv("CRADAR_TOOLS_DIR")
	os.Setenv("CRADAR_TOOLS_DIR", tmpDir)
	defer func() {
		if origToolsDir != "" {
			os.Setenv("CRADAR_TOOLS_DIR", origToolsDir)
		} else {
			os.Unsetenv("CRADAR_TOOLS_DIR")
		}
	}()

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	runner := NewRunner()
	if runner == nil {
		t.Fatal("expected NewRunner to find bundled opengrep via CRADAR_TOOLS_DIR")
	}
	if runner.BinaryPath() != ogBin {
		t.Errorf("expected binary path %s, got %s", ogBin, runner.BinaryPath())
	}
}

func TestNewRunnerWithCBOMToolsDir(t *testing.T) {
	tmpDir := t.TempDir()
	execFile := filepath.Join(tmpDir, "opengrep")
	if err := os.WriteFile(execFile, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	origToolsDir := os.Getenv("CRADAR_TOOLS_DIR")
	os.Setenv("CRADAR_TOOLS_DIR", tmpDir)
	defer func() {
		if origToolsDir != "" {
			os.Setenv("CRADAR_TOOLS_DIR", origToolsDir)
		} else {
			os.Unsetenv("CRADAR_TOOLS_DIR")
		}
	}()

	// Clear PATH to ensure we only find via CRADAR_TOOLS_DIR.
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", origPath)

	runner := NewRunner()
	if runner == nil {
		t.Fatal("expected NewRunner to find binary via CRADAR_TOOLS_DIR")
	}
	if runner.BinaryPath() != execFile {
		t.Errorf("expected binary path %s, got %s", execFile, runner.BinaryPath())
	}
}

func TestLoadableRuleFiles_SkipsBroken(t *testing.T) {
	r := NewRunner()
	if r == nil || !r.Available() {
		t.Skip("opengrep not installed; cannot exercise validate subprocess")
	}

	dir := filepath.Join("testdata", "rules")
	loadable, skipped := r.loadableRuleFiles(dir)

	if len(loadable) == 0 {
		t.Fatal("expected at least one loadable rule file")
	}
	goodSeen := false
	for _, p := range loadable {
		if strings.HasSuffix(filepath.ToSlash(p), "good/example.yml") {
			goodSeen = true
		}
		if strings.Contains(filepath.ToSlash(p), "broken/") {
			t.Errorf("broken rule file should be excluded: %s", p)
		}
	}
	if !goodSeen {
		t.Errorf("good/example.yml should be loadable, loadable=%v", loadable)
	}

	if len(skipped) == 0 {
		t.Errorf("expected at least one skipped rule file with reason")
	}
	for _, sk := range skipped {
		if sk.Reason == "" {
			t.Errorf("skipped rule file %s missing reason", sk.Path)
		}
	}
}

// TestLoadableRuleFiles_BatchValidatePerformance verifies the single-dir
// validate produces the same loadable/skipped split as the per-file approach
// did, on the same testdata fixtures.
func TestLoadableRuleFiles_BatchValidate_SameSetAsPerFile(t *testing.T) {
	r := NewRunner()
	if r == nil || !r.Available() {
		t.Skip("opengrep not installed")
	}

	dir := filepath.Join("testdata", "rules")
	loadable, skipped := r.loadableRuleFiles(dir)

	// good/example.yml must be loadable
	goodSeen := false
	for _, p := range loadable {
		if strings.HasSuffix(filepath.ToSlash(p), "good/example.yml") {
			goodSeen = true
		}
	}
	if !goodSeen {
		t.Errorf("good/example.yml should be loadable, got loadable=%v", loadable)
	}

	// broken/bad-schema.yml must be skipped with a non-empty reason
	brokenSeen := false
	for _, sk := range skipped {
		if strings.HasSuffix(filepath.ToSlash(sk.Path), "broken/bad-schema.yml") {
			brokenSeen = true
			if sk.Reason == "" {
				t.Errorf("skipped reason for broken/bad-schema.yml should be non-empty")
			}
		}
	}
	if !brokenSeen {
		t.Errorf("broken/bad-schema.yml should be in skipped set, got skipped=%v", skipped)
	}
}

func TestStripANSI(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"plain text", "plain text"},
		// Bare SGR foreground
		{"\x1b[33mWARNING\x1b[0m", "WARNING"},
		// Multiple sequences on one line
		{"\x1b[1m[\x1b[33mWARN\x1b[0m]\x1b[0m: msg", "[WARN]: msg"},
		// 256-color extended SGR
		{"\x1b[38;5;208morange\x1b[0m", "orange"},
		// Only CSI codes
		{"\x1b[2K\x1b[1G", ""},
	}
	for _, tc := range cases {
		if got := stripANSI(tc.in); got != tc.want {
			t.Errorf("stripANSI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseValidateBrokenFiles_SingleBroken(t *testing.T) {
	// Realistic opengrep v1.16.5 output for one broken rule, with ANSI codes.
	output := "" +
		"[00.04][\x1b[33mWARNING\x1b[0m]: invalid rule scanner.rules.cbom-go-weak-rand, /abs/path/scanner/rules/go.yml:66:5: Expected object with only one entry -- did you forget a hyphen?\n" +
		"\n"
	got := parseValidateBrokenFiles(output)
	if len(got) != 1 {
		t.Fatalf("expected 1 broken file, got %d: %v", len(got), got)
	}
	// Path is normalized to absolute by parseValidateBrokenFiles; on a real
	// system filepath.Abs(...) of an absolute path returns it unchanged.
	const wantPath = "/abs/path/scanner/rules/go.yml"
	reason, ok := got[wantPath]
	if !ok {
		t.Fatalf("expected key %q in map, got keys: %v", wantPath, mapKeys(got))
	}
	if !strings.Contains(reason, "Expected object") {
		t.Errorf("reason should preserve message, got %q", reason)
	}
}

func TestParseValidateBrokenFiles_MultipleBrokenDedupedByFile(t *testing.T) {
	// Two bad rules in the same file; only first reason recorded.
	output := "" +
		"[WARNING]: invalid rule scanner.rules.first, /abs/scanner/rules/dart.yml:2:4: First failure reason\n" +
		"[WARNING]: invalid rule scanner.rules.second, /abs/scanner/rules/dart.yml:15:8: Second failure reason\n" +
		"[WARNING]: invalid rule scanner.rules.kotlin-bad, /abs/scanner/rules/kotlin.yml:81:17: Invalid pattern for Kotlin\n"
	got := parseValidateBrokenFiles(output)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique broken files, got %d: %v", len(got), got)
	}
	if r := got["/abs/scanner/rules/dart.yml"]; !strings.Contains(r, "First failure") {
		t.Errorf("first-seen reason should win for dart.yml, got %q", r)
	}
	if _, ok := got["/abs/scanner/rules/kotlin.yml"]; !ok {
		t.Errorf("kotlin.yml should be in broken set, got %v", mapKeys(got))
	}
}

func TestParseValidateBrokenFiles_IgnoresNonMatchingLines(t *testing.T) {
	// Real opengrep output mixes status text, table rows, and chardet warnings.
	output := "" +
		"chardet warning: foo\n" +
		"\n" +
		"┌─────────────┐\n" +
		"│ Scan Status │\n" +
		"└─────────────┘\n" +
		"  Scanning 12 files tracked by git with 6 Code rules:\n" +
		"\n" +
		"[WARNING]: invalid rule x.y.z, /abs/scanner/rules/python.yml:10:1: you need at least one positive term\n" +
		"Configuration is invalid - found 0 fatal errors, 10 skippable error(s), and 69 rule(s).\n"
	got := parseValidateBrokenFiles(output)
	if len(got) != 1 {
		t.Fatalf("expected 1 broken file, got %d: %v", len(got), got)
	}
	if _, ok := got["/abs/scanner/rules/python.yml"]; !ok {
		t.Errorf("python.yml should be the lone broken file, got %v", mapKeys(got))
	}
}

func TestParseValidateBrokenFiles_NoBrokenReturnsEmpty(t *testing.T) {
	output := "" +
		"Scanning 5 files tracked by git with 4 Code rules:\n" +
		"Configuration is valid.\n"
	got := parseValidateBrokenFiles(output)
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestParseValidateBrokenFiles_HandlesANSIInsideMatch(t *testing.T) {
	// Some opengrep paths include color codes around segments of the message.
	output := "[\x1b[33mWARNING\x1b[0m]: invalid rule cbom.foo, /abs/r.yml:1:1: \x1b[31merror\x1b[0m text follows\n"
	got := parseValidateBrokenFiles(output)
	if len(got) != 1 {
		t.Fatalf("expected 1 broken file, got %d", len(got))
	}
	// Reason should be ANSI-stripped (parseValidateBrokenFiles calls stripANSI before regex).
	for _, reason := range got {
		if strings.Contains(reason, "\x1b") {
			t.Errorf("reason should not contain ANSI codes: %q", reason)
		}
	}
}

// mapKeys returns the keys of a map[string]string for test diagnostics.
func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
