// Package log is the cradar CLI logging layer built on stdlib log/slog.
//
// A cradar process writes structured records to a per-run JSONL file under
// ~/.cradar/logs/ and emits a small, human-friendly summary to stderr. The
// default sink is JSON; --log-format=text switches the file writer to text.
// Every record carries a stable runID so that lines from a single run can
// be grepped out of an interleaved log directory.
//
// Redaction defaults (unless --log-include-source is set):
//   - Paths are relativised to the scan root.
//   - Source snippets are never recorded.
//   - Environment values are never logged by this package.
package log

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is an enum of the log levels this package exposes.
type Level int

// LevelInfo is the zero value so an unset Config.Level defaults to info.
const (
	LevelInfo Level = iota
	LevelVerbose
	LevelDebug
	LevelQuiet
)

// Format is the file sink's serialisation format.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Config drives Init. Zero values produce sane defaults (info level, json,
// default dir, retain 10 files, redaction on).
type Config struct {
	Level         Level
	Format        Format
	LogFile       string
	LogDir        string
	Retention     int
	IncludeSource bool
	RunID         string
	Now           time.Time
	PID           int
}

var (
	initOnce      sync.Once
	currentLogger *Logger
)

// Logger is the package handle returned by Init. It owns the file handle
// and exposes helpers the rest of the CLI uses.
type Logger struct {
	slog          *slog.Logger
	file          *os.File
	path          string
	runID         string
	includeSource bool
	scanRoot      string
	mu            sync.Mutex
}

// Init configures the global logger. Subsequent calls after the first are
// no-ops to keep cobra PersistentPreRun happy when subcommands reuse init.
func Init(cfg Config) (*Logger, error) {
	var initErr error
	initOnce.Do(func() {
		currentLogger, initErr = build(cfg)
	})
	return currentLogger, initErr
}

// Reset is exposed for tests. Production code must not call it.
func Reset() {
	if currentLogger != nil {
		_ = currentLogger.Close()
	}
	currentLogger = nil
	initOnce = sync.Once{}
}

// Get returns the active logger or a no-op handle if Init has not run.
func Get() *Logger {
	if currentLogger != nil {
		return currentLogger
	}
	return &Logger{slog: slog.New(slog.NewJSONHandler(io.Discard, nil))}
}

func build(cfg Config) (*Logger, error) {
	cfg = applyDefaults(cfg)

	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return nil, fmt.Errorf("log dir: %w", err)
	}

	path := cfg.LogFile
	if path == "" {
		path = filepath.Join(cfg.LogDir, fmt.Sprintf("cradar-%s-%d.log.jsonl",
			cfg.Now.Format("20060102-150405"), cfg.PID))
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}

	opts := &slog.HandlerOptions{Level: levelToSlog(cfg.Level)}
	var handler slog.Handler
	if cfg.Format == FormatText {
		handler = slog.NewTextHandler(f, opts)
	} else {
		handler = slog.NewJSONHandler(f, opts)
	}
	handler = handler.WithAttrs([]slog.Attr{slog.String("runID", cfg.RunID)})

	lg := &Logger{
		slog:          slog.New(handler),
		file:          f,
		path:          path,
		runID:         cfg.RunID,
		includeSource: cfg.IncludeSource,
	}

	if cfg.LogFile == "" && cfg.Retention > 0 {
		lg.pruneOld(cfg.LogDir, cfg.Retention)
	}

	return lg, nil
}

func applyDefaults(cfg Config) Config {
	if cfg.Now.IsZero() {
		cfg.Now = time.Now()
	}
	if cfg.PID == 0 {
		cfg.PID = os.Getpid()
	}
	if cfg.Format == "" {
		cfg.Format = FormatJSON
	}
	if cfg.Retention == 0 {
		cfg.Retention = 10
	}
	if cfg.RunID == "" {
		cfg.RunID = newRunID(cfg.Now, cfg.PID)
	}
	if cfg.LogDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfg.LogDir = filepath.Join(home, ".cradar", "logs")
		} else {
			cfg.LogDir = filepath.Join(os.TempDir(), "cradar-logs")
		}
	}
	return cfg
}

func newRunID(t time.Time, pid int) string {
	return fmt.Sprintf("%s-%d", t.UTC().Format("20060102T150405Z"), pid)
}

func levelToSlog(l Level) slog.Level {
	switch l {
	case LevelQuiet:
		return slog.LevelError
	case LevelVerbose:
		return slog.LevelDebug + 1 // between info and debug → still prints info
	case LevelDebug:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// pruneOld keeps only the newest N `cradar-*.log.jsonl` files in dir.
// Errors are swallowed — log rotation must never prevent the CLI from running.
func (lg *Logger) pruneOld(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type entry struct {
		path string
		mod  time.Time
	}
	var files []entry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "cradar-") || !strings.HasSuffix(name, ".log.jsonl") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, entry{filepath.Join(dir, name), info.ModTime()})
	}
	if len(files) <= keep {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	for _, old := range files[keep:] {
		_ = os.Remove(old.path)
	}
}

// Path returns the active log file path (useful for "see $path for details" UX).
func (lg *Logger) Path() string { return lg.path }

// RunID returns the per-process correlation id.
func (lg *Logger) RunID() string { return lg.runID }

// SetScanRoot records the root directory used to relativise file paths in
// log records. Pass an absolute path.
func (lg *Logger) SetScanRoot(root string) {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	lg.scanRoot = root
}

// Close flushes and closes the file handle.
func (lg *Logger) Close() error {
	if lg == nil || lg.file == nil {
		return nil
	}
	return lg.file.Close()
}

// RedactPath returns a relative path against the configured scan root, or
// the original string if no root is set or the path is not under it.
func (lg *Logger) RedactPath(p string) string {
	if lg == nil || p == "" {
		return p
	}
	lg.mu.Lock()
	root := lg.scanRoot
	lg.mu.Unlock()
	if root == "" {
		return p
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return rel
}

// IncludeSource reports whether source snippets may be logged.
func (lg *Logger) IncludeSource() bool { return lg != nil && lg.includeSource }

// Debug, Info, Warn, Error wrap slog.Logger.
func (lg *Logger) Debug(msg string, args ...any) { lg.slog.Debug(msg, args...) }
func (lg *Logger) Info(msg string, args ...any)  { lg.slog.Info(msg, args...) }
func (lg *Logger) Warn(msg string, args ...any)  { lg.slog.Warn(msg, args...) }
func (lg *Logger) Error(msg string, args ...any) { lg.slog.Error(msg, args...) }

// With returns a child logger with additional attributes. The child shares
// the parent's file handle and scan root — closing it is a no-op.
func (lg *Logger) With(args ...any) *Logger {
	return &Logger{
		slog:          lg.slog.With(args...),
		path:          lg.path,
		runID:         lg.runID,
		includeSource: lg.includeSource,
		scanRoot:      lg.scanRoot,
	}
}

// ErrLogPath is returned (wrapped) when the logger cannot be initialised.
// Cradar should fall back to a no-op logger rather than abort.
var ErrLogPath = errors.New("cradar: log path unusable")
