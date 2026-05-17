package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetForTest clears the package-level singleton. Tests that call Init
// must defer this so they do not poison each other.
func resetForTest(t *testing.T) {
	t.Helper()
	Reset()
}

func TestInit_WritesJSONL(t *testing.T) {
	defer resetForTest(t)
	dir := t.TempDir()
	lg, err := Init(Config{
		LogDir: dir,
		Now:    time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC),
		PID:    1234,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if lg.Path() == "" {
		t.Fatal("empty log path")
	}
	if !strings.HasSuffix(lg.Path(), ".log.jsonl") {
		t.Errorf("path suffix mismatch: %s", lg.Path())
	}

	lg.Info("hello", "k", "v")
	_ = lg.Close()

	data, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	line := strings.TrimRight(string(data), "\n")
	if line == "" {
		t.Fatalf("log file empty: path=%s", lg.Path())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("parse jsonl: %v (%s)", err, line)
	}
	if rec["msg"] != "hello" || rec["k"] != "v" {
		t.Errorf("missing fields: %+v", rec)
	}
	if rec["runID"] == "" || rec["runID"] == nil {
		t.Error("runID not embedded")
	}
}

func TestRedactPath_UnderScanRoot(t *testing.T) {
	defer resetForTest(t)
	lg, err := Init(Config{LogDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.SetScanRoot("/home/u/proj")
	if got := lg.RedactPath("/home/u/proj/src/x.go"); got != "src/x.go" {
		t.Errorf("expected src/x.go, got %s", got)
	}
	if got := lg.RedactPath("/etc/passwd"); got != "/etc/passwd" {
		t.Errorf("outside-root path should not be rewritten, got %s", got)
	}
}

func TestIncludeSource_DefaultOff(t *testing.T) {
	defer resetForTest(t)
	lg, err := Init(Config{LogDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if lg.IncludeSource() {
		t.Error("IncludeSource must be false by default")
	}
}

// TestRedaction_LogNeverContainsAbsolutePath exercises the full write path:
// a caller deliberately tries to sneak an absolute path into a log record
// via a structured attribute by using RedactPath first. The on-disk log
// must not contain the original absolute prefix.
func TestRedaction_LogNeverContainsAbsolutePath(t *testing.T) {
	defer resetForTest(t)
	dir := t.TempDir()
	lg, err := Init(Config{LogDir: dir, Now: time.Now(), PID: 1})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.SetScanRoot("/home/user/secret-project")
	abs := "/home/user/secret-project/src/keys.go"
	lg.Info("finding", "file", lg.RedactPath(abs))
	_ = lg.Close()

	data, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(data), "/home/user/secret-project") {
		t.Errorf("absolute scan-root leaked into log record:\n%s", data)
	}
	if !strings.Contains(string(data), "src/keys.go") {
		t.Errorf("redacted relative path missing from log:\n%s", data)
	}
}

// TestRedaction_OutsideRootIsPreserved guards against RedactPath silently
// rewriting paths that are NOT under the scan root (e.g. /etc/passwd,
// system binaries, user home). Rewriting those would make the log
// misleading — we want the absolute path preserved.
func TestRedaction_OutsideRootIsPreserved(t *testing.T) {
	defer resetForTest(t)
	lg, err := Init(Config{LogDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.SetScanRoot("/home/user/proj")
	for _, p := range []string{"/etc/passwd", "/usr/bin/sh", "/tmp/foo"} {
		if got := lg.RedactPath(p); got != p {
			t.Errorf("RedactPath(%q) rewrote to %q; must be preserved", p, got)
		}
	}
}

func TestPruneOld_KeepsLastN(t *testing.T) {
	defer resetForTest(t)
	dir := t.TempDir()
	// Seed 15 files with mtimes in the past, older as index grows. The fresh
	// log file created by Init has mtime = now, so it is the newest and must
	// survive the prune alongside 4 of the seeds.
	for i := range 15 {
		p := filepath.Join(dir, "cradar-20260415-"+pad2(i)+".log.jsonl")
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		past := time.Now().Add(-time.Duration(i+1) * time.Minute)
		_ = os.Chtimes(p, past, past)
	}
	lg, err := Init(Config{LogDir: dir, Retention: 5})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer lg.Close()

	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log.jsonl") {
			count++
		}
	}
	// Retention=5 is the cap, and it includes the fresh file Init created.
	if count != 5 {
		t.Errorf("expected 5 files after prune, got %d", count)
	}
}

func TestNewRunID_StableShape(t *testing.T) {
	id := newRunID(time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC), 42)
	if id != "20260415T100000Z-42" {
		t.Errorf("unexpected runID: %s", id)
	}
}

func pad2(i int) string {
	if i < 10 {
		return "0" + itoa(i)
	}
	return itoa(i)
}

func itoa(i int) string { return string(rune('0'+i/10)) + string(rune('0'+i%10)) }

func TestLogger_ScannerLifecycleEvents(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	lg.ScannerStart("python", "/tmp/proj")
	lg.ScannerComplete("python", 3, 12*time.Millisecond)
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", "")

	if err := lg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		`"event":"scanner_start"`,
		`"event":"scanner_complete"`,
		`"event":"finding_emitted"`,
		`"scanner":"python"`,
		`"ruleID":"cbom-py-md5"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log missing %q\n--- log ---\n%s", want, got)
		}
	}
}

func TestLogger_SourceFieldOmittedWhenIncludeSourceFalse(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, IncludeSource: false, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", "hashlib.md5(secret)")
	_ = lg.Close()

	data, _ := os.ReadFile(lg.Path())
	if strings.Contains(string(data), "hashlib.md5") {
		t.Errorf("source snippet leaked when IncludeSource=false:\n%s", string(data))
	}
}

func TestLogger_SourceFieldPopulatedWhenIncludeSourceTrue(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, IncludeSource: true, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", "hashlib.md5(b'x')")
	_ = lg.Close()

	data, _ := os.ReadFile(lg.Path())
	if !strings.Contains(string(data), "hashlib.md5") {
		t.Errorf("source snippet should appear when IncludeSource=true:\n%s", string(data))
	}
}

func TestLogger_SourceFieldTruncatedAt200Chars(t *testing.T) {
	dir := t.TempDir()
	Reset()
	t.Cleanup(Reset)

	lg, err := Init(Config{LogDir: dir, Level: LevelDebug, IncludeSource: true, RunID: "test-run"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	long := strings.Repeat("a", 500)
	lg.FindingEmitted("python", "cbom-py-md5", "high", "/tmp/proj/a.py", long)
	_ = lg.Close()

	data, _ := os.ReadFile(lg.Path())
	if strings.Contains(string(data), strings.Repeat("a", 250)) {
		t.Errorf("source snippet was not truncated:\n%s", string(data))
	}
}
