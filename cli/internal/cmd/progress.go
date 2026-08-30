package cmd

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// ProgressOpts configures progress emission cadence.
type ProgressOpts struct {
	Quiet          bool
	Verbose        bool
	HeartbeatEvery int           // emit one heartbeat per N files (<=0 disables count-based)
	MinInterval    time.Duration // also emit if MinInterval has elapsed (<=0 disables time-based)
	MinFiles       int           // suppress heartbeats entirely if total < MinFiles
}

// DefaultProgressOpts returns reasonable defaults.
func DefaultProgressOpts() ProgressOpts {
	return ProgressOpts{HeartbeatEvery: 100, MinInterval: 2 * time.Second, MinFiles: 50}
}

type progressEmitter struct {
	w     io.Writer
	opts  ProgressOpts
	mu    sync.Mutex
	count int
	last  time.Time
	langs map[string]int
}

func newProgressEmitter(w io.Writer, opts ProgressOpts) *progressEmitter {
	return &progressEmitter{w: w, opts: opts, last: time.Now(), langs: map[string]int{}}
}

// WalkedFile is called by the walker after each file is processed.
func (p *progressEmitter) WalkedFile(lang, path string) {
	if p.opts.Quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	if lang != "" {
		p.langs[lang]++
	}
	if p.opts.Verbose {
		fmt.Fprintf(p.w, "[scan] walk %s: %s\n", lang, path)
	}
	if p.opts.HeartbeatEvery <= 0 {
		return
	}
	due := p.count%p.opts.HeartbeatEvery == 0
	timeDue := p.opts.MinInterval > 0 && time.Since(p.last) >= p.opts.MinInterval
	if !due && !timeDue {
		return
	}
	if p.opts.MinFiles > 0 && p.count < p.opts.MinFiles {
		return
	}
	p.emitHeartbeat()
	p.last = time.Now()
}

func (p *progressEmitter) emitHeartbeat() {
	type kv struct {
		k string
		v int
	}
	ks := make([]kv, 0, len(p.langs))
	for k, v := range p.langs {
		ks = append(ks, kv{k, v})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].v > ks[j].v })
	parts := make([]string, 0, len(ks))
	for _, e := range ks {
		parts = append(parts, fmt.Sprintf("%s: %d", e.k, e.v))
	}
	suffix := ""
	if len(parts) > 0 {
		suffix = " (" + joinLimit(parts, 4) + ")"
	}
	fmt.Fprintf(p.w, "[scan] walked %d files%s\n", p.count, suffix)
}

// PassStart announces the start of a scan pass.
func (p *progressEmitter) PassStart(pass int, name string, fileCount int) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.w, "[scan] pass %d: %s starting (%d files)\n", pass, name, fileCount)
}

// PassComplete announces the end of a scan pass.
func (p *progressEmitter) PassComplete(pass int, name string, elapsed time.Duration, findings int) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.w, "[scan] pass %d: %s complete (%s, %d findings)\n",
		pass, name, elapsed.Round(time.Millisecond), findings)
}

// PassCompleteInline announces the end of a pass that runs *within* another
// pass's traversal and therefore has no separable elapsed time. YARA-X
// (Pass 3) executes as a universal inside the Pass-1 walk, so only a finding
// count is meaningful. Without this, a completed Pass 3 emitted nothing and
// users concluded it never ran (see issue #113).
func (p *progressEmitter) PassCompleteInline(pass int, name string, findings int) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.w, "[scan] pass %d: %s complete (%d findings)\n", pass, name, findings)
}

// PassSkipped announces that a requested pass did not execute, with the
// reason. Makes a soft-skip visible instead of silent (issue #113).
func (p *progressEmitter) PassSkipped(pass int, name, reason string) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.w, "[scan] pass %d: %s skipped — %s\n", pass, name, reason)
}

func joinLimit(parts []string, limit int) string {
	if len(parts) <= limit {
		return joinComma(parts)
	}
	return joinComma(parts[:limit]) + ", ..."
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
