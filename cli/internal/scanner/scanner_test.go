package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// mockScanner is a test implementation of the Scanner interface.
type mockScanner struct {
	name       string
	extensions []string
	findings   []types.Finding
	err        error
}

func (m *mockScanner) Name() string                { return m.name }
func (m *mockScanner) Extensions() []string         { return m.extensions }
func (m *mockScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if len(r.All()) != 0 {
		t.Errorf("expected empty registry, got %d scanners", len(r.All()))
	}
	if r.ForExtension(".py") != nil {
		t.Error("expected nil for unknown extension")
	}
}

func TestRegisterAndForExtension(t *testing.T) {
	r := NewRegistry()
	mock := &mockScanner{
		name:       "python",
		extensions: []string{".py", ".pyw"},
	}
	r.Register(mock)

	if len(r.All()) != 1 {
		t.Errorf("expected 1 scanner, got %d", len(r.All()))
	}
	if r.All()[0].Name() != "python" {
		t.Errorf("expected scanner name 'python', got %q", r.All()[0].Name())
	}

	// Test extension lookup
	s := r.ForExtension(".py")
	if s == nil {
		t.Fatal("expected scanner for .py, got nil")
	}
	if s.Name() != "python" {
		t.Errorf("expected 'python' scanner for .py, got %q", s.Name())
	}

	s = r.ForExtension(".pyw")
	if s == nil {
		t.Fatal("expected scanner for .pyw, got nil")
	}
	if s.Name() != "python" {
		t.Errorf("expected 'python' scanner for .pyw, got %q", s.Name())
	}

	// Unknown extension
	if r.ForExtension(".rs") != nil {
		t.Error("expected nil for unknown extension .rs")
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.py", ".py"},
		{"src/app.js", ".js"},
		{"lib/crypto.go", ".go"},
		{"UPPER.PY", ".py"},
		{"Mixed.Py", ".py"},
		{"noextension", ""},
		{"path/to/Makefile", ""},
		{".gitignore", ".gitignore"},
	}

	for _, tt := range tests {
		got := DetectLanguage(tt.path)
		if got != tt.want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestScanDir(t *testing.T) {
	// Create a temp directory with a test file
	tmpDir := t.TempDir()

	testContent := []byte("import hashlib\nhashlib.md5(b'test')\n")
	testFile := filepath.Join(tmpDir, "test.py")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Create a non-matching file
	otherFile := filepath.Join(tmpDir, "readme.txt")
	if err := os.WriteFile(otherFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write other file: %v", err)
	}

	// Create a .git directory that should be skipped
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git dir: %v", err)
	}
	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("git config"), 0644); err != nil {
		t.Fatalf("failed to write git file: %v", err)
	}

	dummyFinding := types.Finding{
		ID:        "TEST-001",
		AssetType: types.AssetAlgorithm,
		Name:      "MD5",
		Location: types.Location{
			File:      "test.py",
			StartLine: 2,
			StartCol:  1,
			EndLine:   2,
			EndCol:    20,
			Snippet:   "hashlib.md5(b'test')",
		},
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceHigh,
	}

	mock := &mockScanner{
		name:       "python",
		extensions: []string{".py"},
		findings:   []types.Finding{dummyFinding},
	}

	registry := NewRegistry()
	registry.Register(mock)

	result, err := ScanDir(tmpDir, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if result.Target != tmpDir {
		t.Errorf("expected target %q, got %q", tmpDir, result.Target)
	}
	if result.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.FilesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Name != "MD5" {
		t.Errorf("expected finding name 'MD5', got %q", result.Findings[0].Name)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %d: %v", len(result.Errors), result.Errors)
	}
	if result.StartTime.IsZero() {
		t.Error("expected non-zero StartTime")
	}
	if result.EndTime.IsZero() {
		t.Error("expected non-zero EndTime")
	}
	if len(result.PassesRun) != 1 || result.PassesRun[0] != 1 {
		t.Errorf("expected PassesRun [1], got %v", result.PassesRun)
	}
}

func TestScanDirSkipsDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create directories that should be skipped
	skippedDirs := []string{"node_modules", "__pycache__", ".venv", "vendor", "dist", "build"}
	for _, dir := range skippedDirs {
		dirPath := filepath.Join(tmpDir, dir)
		if err := os.Mkdir(dirPath, 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", dir, err)
		}
		// Put a .py file inside each skipped dir
		pyFile := filepath.Join(dirPath, "should_skip.py")
		if err := os.WriteFile(pyFile, []byte("import os"), 0644); err != nil {
			t.Fatalf("failed to write file in %s: %v", dir, err)
		}
	}

	mock := &mockScanner{
		name:       "python",
		extensions: []string{".py"},
		findings:   []types.Finding{},
	}
	registry := NewRegistry()
	registry.Register(mock)

	result, err := ScanDir(tmpDir, registry, []int{1})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}
	if result.FilesScanned != 0 {
		t.Errorf("expected 0 files scanned (all dirs skipped), got %d", result.FilesScanned)
	}
}
