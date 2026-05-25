package yarax

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeBinary creates a tiny shell-script "binary" with the given
// name in dir. The script is marked executable so isExecutable returns
// true. Returns the absolute path.
func writeFakeBinary(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return path
}

// clearLookupEnv blanks the env vars NewRunner consults so a test
// controls the lookup order deterministically. Restores them on
// cleanup.
func clearLookupEnv(t *testing.T) {
	t.Helper()
	prev := map[string]string{
		"CRADAR_TOOLS_DIR": os.Getenv("CRADAR_TOOLS_DIR"),
		"PATH":             os.Getenv("PATH"),
		"HOME":             os.Getenv("HOME"),
	}
	t.Setenv("CRADAR_TOOLS_DIR", "")
	t.Setenv("PATH", "")
	// HOME is left alone here — individual tests redirect it via
	// t.Setenv("HOME", ...) when they want the ~/.cradar/tools lookup
	// to find a fixture. Clearing it would cripple unrelated tests
	// that read HOME (none today, but better to be explicit).
	t.Cleanup(func() {
		for k, v := range prev {
			_ = os.Setenv(k, v)
		}
	})
}

func TestNewRunner_LookupOrder(t *testing.T) {
	// Lookup precedence (per package contract):
	//   1. next-to-self binary  (os.Executable() dir + /yr)
	//   2. $CRADAR_TOOLS_DIR/yr
	//   3. ~/.cradar/tools/yr
	//   4. $PATH
	//
	// The "next-to-self" candidate is implicit (it requires the test
	// binary to live next to a 'yr' file, which we don't want to litter
	// the harness with); we exercise the remaining three explicitly.
	if runtime.GOOS == "windows" {
		t.Skip("isExecutable uses unix-style exec bits; lookup order test runs on unix only")
	}

	t.Run("CRADAR_TOOLS_DIR wins over HOME and PATH", func(t *testing.T) {
		clearLookupEnv(t)
		tools := t.TempDir()
		home := t.TempDir()
		path := t.TempDir()

		homeTools := filepath.Join(home, ".cradar", "tools")
		if err := os.MkdirAll(homeTools, 0o755); err != nil {
			t.Fatalf("mkdir home tools: %v", err)
		}

		expected := writeFakeBinary(t, tools, "yr")
		_ = writeFakeBinary(t, homeTools, "yr") // noise
		_ = writeFakeBinary(t, path, "yr")      // noise

		t.Setenv("CRADAR_TOOLS_DIR", tools)
		t.Setenv("HOME", home)
		t.Setenv("PATH", path)

		r := NewRunner()
		if r == nil || r.BinaryPath() != expected {
			t.Fatalf("expected CRADAR_TOOLS_DIR to win; got %v", r)
		}
	})

	t.Run("HOME wins over PATH when CRADAR_TOOLS_DIR is empty", func(t *testing.T) {
		clearLookupEnv(t)
		home := t.TempDir()
		path := t.TempDir()

		homeTools := filepath.Join(home, ".cradar", "tools")
		if err := os.MkdirAll(homeTools, 0o755); err != nil {
			t.Fatalf("mkdir home tools: %v", err)
		}
		expected := writeFakeBinary(t, homeTools, "yr")
		_ = writeFakeBinary(t, path, "yr") // noise

		t.Setenv("HOME", home)
		t.Setenv("PATH", path)

		r := NewRunner()
		if r == nil || r.BinaryPath() != expected {
			t.Fatalf("expected HOME candidate to win; got %v", r)
		}
	})

	t.Run("PATH wins when nothing else resolves", func(t *testing.T) {
		clearLookupEnv(t)
		path := t.TempDir()
		expected := writeFakeBinary(t, path, "yr")

		// Point HOME at an empty dir so ~/.cradar/tools/yr doesn't resolve.
		emptyHome := t.TempDir()
		t.Setenv("HOME", emptyHome)
		t.Setenv("PATH", path)

		r := NewRunner()
		if r == nil || r.BinaryPath() != expected {
			t.Fatalf("expected PATH lookup to win; got %v", r)
		}
	})

	t.Run("nil when nothing resolves", func(t *testing.T) {
		clearLookupEnv(t)
		emptyHome := t.TempDir()
		t.Setenv("HOME", emptyHome)
		// PATH already blank from clearLookupEnv.

		r := NewRunner()
		if r != nil {
			t.Fatalf("expected nil runner, got %v", r)
		}
	})
}

func TestRunner_AvailableReportsTrueWhenBinaryPresent(t *testing.T) {
	tmp := t.TempDir()
	bin := writeFakeBinary(t, tmp, "yr")

	r := NewRunnerWithBinary(bin)
	if r == nil || !r.Available() {
		t.Fatalf("expected Available() = true for executable binary at %s", bin)
	}
	if r.BinaryPath() != bin {
		t.Fatalf("expected BinaryPath() = %q, got %q", bin, r.BinaryPath())
	}
}

func TestRunner_AvailableFalseOnNil(t *testing.T) {
	var r *Runner
	if r.Available() {
		t.Error("expected Available() = false on nil runner")
	}
	if r.BinaryPath() != "" {
		t.Errorf("expected BinaryPath() = \"\" on nil runner, got %q", r.BinaryPath())
	}
}

func TestRunner_ScanSoftSkipsWhenAbsent(t *testing.T) {
	// nil runner — soft skip, no error, no findings.
	var r *Runner
	findings, err := r.Scan("anything.so", "/tmp/whatever")
	if err != nil {
		t.Errorf("expected nil error for nil-runner scan, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for nil-runner scan, got %v", findings)
	}
}

func TestRunner_ScanSoftSkipsWhenNoRulesDirArg(t *testing.T) {
	// Runner present but caller passes "" — soft skip without invoking yr.
	tmp := t.TempDir()
	bin := writeFakeBinary(t, tmp, "yr")
	r := NewRunnerWithBinary(bin)

	findings, err := r.Scan("anything.so", "")
	if err != nil {
		t.Errorf("expected nil error for empty rules-dir, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty rules-dir, got %v", findings)
	}
}

func TestRunner_ScanSoftSkipsWhenRulesDirEmpty(t *testing.T) {
	// Runner present, rules dir present but contains no .yar/.yara —
	// expected runtime state in Sub-PR A. Should soft skip without
	// invoking yr (which would also exit 0, but we want to spare the
	// subprocess startup cost).
	tmp := t.TempDir()
	bin := writeFakeBinary(t, tmp, "yr")
	r := NewRunnerWithBinary(bin)

	emptyRules := t.TempDir()
	// Sprinkle some non-rule files to make sure they don't trip the
	// "has rules" detector.
	if err := os.WriteFile(filepath.Join(emptyRules, "README.md"), []byte("# rules"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}

	findings, err := r.Scan("anything.so", emptyRules)
	if err != nil {
		t.Errorf("expected nil error for empty rules dir, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty rules dir, got %v", findings)
	}
}

func TestRunner_ScanSoftSkipsWhenRulesDirMissing(t *testing.T) {
	tmp := t.TempDir()
	bin := writeFakeBinary(t, tmp, "yr")
	r := NewRunnerWithBinary(bin)

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	findings, err := r.Scan("anything.so", missing)
	if err != nil {
		t.Errorf("expected nil error for missing rules dir, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for missing rules dir, got %v", findings)
	}
}

func TestRulesDir_DefaultsToEmbedded(t *testing.T) {
	// Override wins over the embedded default.
	t.Setenv("CRADAR_YARA_RULES_DIR", "/some/rules")
	if got := RulesDir(); got != "/some/rules" {
		t.Errorf("expected RulesDir() = %q, got %q", "/some/rules", got)
	}

	// Empty env falls back to the extracted embedded ruleset (Sub-PR B).
	// We don't pin a specific path — extraction lands in os.TempDir() —
	// but we assert it's non-empty and contains at least one .yar file.
	t.Setenv("CRADAR_YARA_RULES_DIR", "")
	dir := RulesDir()
	if dir == "" {
		t.Fatalf("expected RulesDir() to fall back to extracted embedded rules, got empty")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading extracted rules dir %q: %v", dir, err)
	}
	hasYar := false
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".yar") {
			hasYar = true
			break
		}
	}
	if !hasYar {
		t.Errorf("expected at least one .yar file in extracted rules dir %q", dir)
	}
}
