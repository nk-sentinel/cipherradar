package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults_SkipDirsAndFiles(t *testing.T) {
	m := New(t.TempDir(), true, true, false)

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

func TestScanBinaries_KeepsBuildOutputDirs(t *testing.T) {
	// Pass 3 active: build-output dirs must remain scannable (binaries live
	// there), but vendor/dependency/tool dirs are still pruned.
	m := New(t.TempDir(), true, true, true)

	for _, d := range []string{"target", "build", "dist", "out", "bin", "obj"} {
		if m.SkipDir(d, d) {
			t.Errorf("with Pass 3 active, build-output dir %q must NOT be skipped", d)
		}
	}
	// Vendor/dependency/tool dirs are still skipped even under Pass 3.
	for _, d := range []string{"node_modules", "vendor", ".git", "__pycache__", ".gradle"} {
		if !m.SkipDir(d, d) {
			t.Errorf("with Pass 3 active, vendor dir %q should still be skipped", d)
		}
	}

	// Sanity: without Pass 3, build-output dirs are skipped as before.
	m2 := New(t.TempDir(), true, true, false)
	for _, d := range []string{"target", "build", "dist", "out", "bin", "obj"} {
		if !m2.SkipDir(d, d) {
			t.Errorf("without Pass 3, build-output dir %q should be skipped", d)
		}
	}
}

func TestNoDefaults_IgnoresNothingBuiltIn(t *testing.T) {
	m := New(t.TempDir(), false, false, false)
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
	m := New(root, true, true, false)
	if !m.SkipDir("generated", "generated") {
		t.Error("expected .gitignore'd dir to be skipped")
	}
	if !m.SkipFile("secret.txt") {
		t.Error("expected .gitignore'd file to be skipped")
	}
	// With gitignore disabled, not skipped.
	m2 := New(root, true, false, false)
	if m2.SkipFile("secret.txt") {
		t.Error("with --no-gitignore, gitignore'd file should not be skipped")
	}
}

func TestCradarignoreRespected(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".cradarignore"), []byte("fixtures/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New(root, false, false, false) // even with defaults+gitignore off, .cradarignore applies
	if !m.SkipDir("fixtures", "fixtures") {
		t.Error("expected .cradarignore'd dir to be skipped")
	}
}
