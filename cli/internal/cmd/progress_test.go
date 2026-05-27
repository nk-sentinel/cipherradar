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
