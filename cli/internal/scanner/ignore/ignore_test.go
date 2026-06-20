package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults_SkipDirsAndFiles(t *testing.T) {
	m := New(t.TempDir(), true, true)

	for _, d := range []string{"node_modules", "target", "dist", ".scannerwork", "Pods", "__pycache__"} {
		if !m.SkipDir(d, d) {
			t.Errorf("expected default skip of dir %q", d)
		}
	}
	// Must NOT skip legit scan-target dirs.
	for _, d := range []string{"certs", "binaries", "src", "config"} {
		if m.SkipDir(d, d) {
			t.Errorf("dir %q should NOT be default-skipped", d)
		}
	}
	for _, f := range []string{"app.min.js", "vendor.bundle.js", "main.js.map", ".cradar-baseline.json"} {
		if !m.SkipFile(f) {
			t.Errorf("expected default skip of file %q", f)
		}
	}
	// Must NOT skip legit targets.
	for _, f := range []string{"nginx.conf", "server.key", "cert.pem", "app.js"} {
		if m.SkipFile(f) {
			t.Errorf("file %q should NOT be default-skipped", f)
		}
	}
}

func TestNoDefaults_IgnoresNothingBuiltIn(t *testing.T) {
	m := New(t.TempDir(), false, false)
	if m.SkipDir("node_modules", "node_modules") {
		t.Error("with defaults off, node_modules should not be skipped")
	}
	if m.SkipFile("app.min.js") {
		t.Error("with defaults off, *.min.js should not be skipped")
	}
}

func TestGitignoreRespected(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("generated/\nsecret.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New(root, true, true)
	if !m.SkipDir("generated", "generated") {
		t.Error("expected .gitignore'd dir to be skipped")
	}
	if !m.SkipFile("secret.txt") {
		t.Error("expected .gitignore'd file to be skipped")
	}
	// With gitignore disabled, not skipped.
	m2 := New(root, true, false)
	if m2.SkipFile("secret.txt") {
		t.Error("with --no-gitignore, gitignore'd file should not be skipped")
	}
}

func TestCradarignoreRespected(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".cradarignore"), []byte("fixtures/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New(root, false, false) // even with defaults+gitignore off, .cradarignore applies
	if !m.SkipDir("fixtures", "fixtures") {
		t.Error("expected .cradarignore'd dir to be skipped")
	}
}
