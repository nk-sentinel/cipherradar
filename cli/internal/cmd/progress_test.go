package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgressEmitter_RateLimit(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, ProgressOpts{HeartbeatEvery: 100, MinFiles: 0, MinInterval: 100 * time.Millisecond})
	for i := 0; i < 350; i++ {
		p.WalkedFile("python", "f.py")
	}
	out := buf.String()
	if got := strings.Count(out, "[scan] walked"); got != 3 {
		t.Errorf("got %d heartbeats, want 3:\n%s", got, out)
	}
}

func TestProgressEmitter_QuietSuppresses(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, ProgressOpts{Quiet: true})
	for i := 0; i < 500; i++ {
		p.WalkedFile("go", "f.go")
	}
	p.PassStart(1, "tree-sitter", 412)
	if buf.Len() != 0 {
		t.Errorf("quiet mode should produce no output, got: %q", buf.String())
	}
}

func TestProgressEmitter_SuppressBelowMinFiles(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, ProgressOpts{HeartbeatEvery: 10, MinFiles: 50})
	for i := 0; i < 30; i++ {
		p.WalkedFile("go", "f.go")
	}
	if strings.Contains(buf.String(), "walked") {
		t.Errorf("should suppress heartbeat when total < MinFiles; got: %q", buf.String())
	}
}

// PassCompleteInline announces a pass that ran within another pass's traversal
// (YARA-X/Pass 3 runs inside the Pass-1 walk) — a finding count, no timing.
// Regression guard for issue #113: a completed Pass 3 must not be silent.
func TestProgressEmitter_PassCompleteInline(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, DefaultProgressOpts())
	p.PassCompleteInline(3, "yara-x", 7)
	out := buf.String()
	if !strings.Contains(out, "pass 3: yara-x complete (7 findings)") {
		t.Errorf("unexpected inline completion line: %q", out)
	}
	// Must not imply a separate elapsed time (no "ms"/parenthesised duration).
	if strings.Contains(out, "ms") {
		t.Errorf("inline completion should carry no timing, got: %q", out)
	}

	var quiet bytes.Buffer
	pq := newProgressEmitter(&quiet, ProgressOpts{Quiet: true})
	pq.PassCompleteInline(3, "yara-x", 7)
	if quiet.Len() != 0 {
		t.Errorf("quiet mode should suppress inline completion, got: %q", quiet.String())
	}
}

// PassSkipped makes a soft-skipped pass visible instead of silent (issue #113).
func TestProgressEmitter_PassSkipped(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, DefaultProgressOpts())
	p.PassSkipped(3, "yara-x", "yara-x (yr) not found")
	if got := buf.String(); !strings.Contains(got, "pass 3: yara-x skipped — yara-x (yr) not found") {
		t.Errorf("unexpected skip line: %q", got)
	}

	var quiet bytes.Buffer
	pq := newProgressEmitter(&quiet, ProgressOpts{Quiet: true})
	pq.PassSkipped(3, "yara-x", "reason")
	if quiet.Len() != 0 {
		t.Errorf("quiet mode should suppress skip line, got: %q", quiet.String())
	}
}
