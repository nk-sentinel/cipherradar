package yarax

import (
	"reflect"
	"sort"
	"testing"
)

func TestScanner_Name(t *testing.T) {
	s := New()
	if got := s.Name(); got != "yarax" {
		t.Errorf("expected Name() = %q, got %q", "yarax", got)
	}
}

func TestScanner_RegisteredExtensions(t *testing.T) {
	s := New()
	got := s.Extensions()
	sort.Strings(got)
	expected := []string{
		".a", ".class", ".dll", ".dylib", ".exe",
		".jar", ".o", ".so", ".wasm", ".whl",
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("expected Extensions() = %v, got %v", expected, got)
	}
}

func TestScanner_ScanFileSoftSkipsWhenRunnerAbsent(t *testing.T) {
	// Scanner with no runner — soft-skip path. Must return nil, nil
	// without panicking and without consulting the rules dir.
	s := NewWithRunner(nil, "/some/rules/dir")
	findings, err := s.ScanFile("openssl-versions.so", []byte("\x7fELF"))
	if err != nil {
		t.Errorf("expected nil error from runner-less scanner, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings from runner-less scanner, got %v", findings)
	}
}

func TestScanner_ScanFileSoftSkipsWhenNoRules(t *testing.T) {
	// Scanner with a runner but empty rules dir — Sub-PR A's expected
	// runtime state. Soft-skip without invoking yr.
	tmp := t.TempDir()
	bin := writeFakeBinary(t, tmp, "yr")
	r := NewRunnerWithBinary(bin)
	s := NewWithRunner(r, "")

	findings, err := s.ScanFile("openssl-versions.so", []byte("\x7fELF"))
	if err != nil {
		t.Errorf("expected nil error when rules dir is empty, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when rules dir is empty, got %v", findings)
	}
}

func TestScanner_ScanFileSkipsUnsupportedExtensions(t *testing.T) {
	// Files with language extensions (e.g. .py, .go) are handled by
	// language scanners. The internal handlesPath gate excludes them
	// even though the scanner is registered as a Universal.
	tmp := t.TempDir()
	bin := writeFakeBinary(t, tmp, "yr")
	r := NewRunnerWithBinary(bin)
	// Real-looking rules dir so the gate that fires next wouldn't
	// also short-circuit (we want to assert the extension gate
	// specifically).
	rulesDir := t.TempDir()
	s := NewWithRunner(r, rulesDir)

	for _, name := range []string{"foo.py", "foo.go", "foo.js", "foo.rs"} {
		findings, err := s.ScanFile(name, []byte("source"))
		if err != nil {
			t.Errorf("ScanFile(%s): unexpected error %v", name, err)
		}
		if findings != nil {
			t.Errorf("ScanFile(%s): expected nil findings, got %v", name, findings)
		}
	}
}

func TestScanner_HandlesExtensionlessFiles(t *testing.T) {
	// Many Unix binaries (and the CipherRadarTestProj fixtures) have
	// no extension. Verify handlesPath admits them so the e2e probe
	// path works.
	s := New()
	if !s.handlesPath("openssl-versions") {
		t.Error("expected handlesPath to admit extensionless file 'openssl-versions'")
	}
	if !s.handlesPath("/full/path/to/embedded-cert") {
		t.Error("expected handlesPath to admit extensionless file with full path")
	}
}
