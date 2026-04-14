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
