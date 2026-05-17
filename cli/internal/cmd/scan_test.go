package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
)

func TestParsePasses(t *testing.T) {
	tests := []struct {
		input   string
		want    []int
		wantErr bool
	}{
		{"1", []int{1}, false},
		{"1,2", []int{1, 2}, false},
		{"1, 2", []int{1, 2}, false},
		// Pass 3 removed per ADR-033 (Joern dropped, all patterns covered by OpenGrep).
		{"1,2,3", nil, true},
		{"3", nil, true},
		{"", nil, true},
		{"0", nil, true},
		{"4", nil, true},
		{"abc", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePasses(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len(got) = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestScanCommand_CycloneDXJSON(t *testing.T) {
	// Create a temp directory with a Python file that uses hashlib.
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "example.py")
	err := os.WriteFile(pyFile, []byte(`import hashlib
h = hashlib.md5(b"hello")
`), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Run the scan command.
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "-f", "cyclonedx-json"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan command failed: %v", err)
	}

	output := buf.String()

	// Verify it is valid JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\n--- output ---\n%s", err, output)
	}

	// Verify CycloneDX envelope.
	if raw["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", raw["bomFormat"])
	}
	if raw["specVersion"] != "1.7" {
		t.Errorf("specVersion = %v, want 1.7", raw["specVersion"])
	}

	// Verify there is at least one component (MD5 finding).
	components, ok := raw["components"].([]interface{})
	if !ok || len(components) == 0 {
		t.Error("expected at least one component in the output")
	}
}

func TestScanCommand_TextOutput(t *testing.T) {
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "example.py")
	err := os.WriteFile(pyFile, []byte(`import hashlib
h = hashlib.sha256(b"hello")
`), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "-f", "text"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan command failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CipherRadar") {
		t.Error("text output should contain 'CipherRadar' in the header")
	}
	if !strings.Contains(output, "SCAN COMPLETE") {
		t.Error("text output should contain 'SCAN COMPLETE' banner")
	}
	if !strings.Contains(output, "Python") {
		t.Error("text output should list Python in language breakdown")
	}
}

func TestScanCommand_OutputToFile(t *testing.T) {
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "example.py")
	err := os.WriteFile(pyFile, []byte(`import hashlib
h = hashlib.md5(b"hello")
`), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	outFile := filepath.Join(tmpDir, "output.json")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "-f", "cyclonedx-json", "-o", outFile})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan command failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
	if raw["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", raw["bomFormat"])
	}
}

func TestScanCommand_PushFlagRegistered(t *testing.T) {
	// Verify --push and related flags are registered on the scan command.
	flags := []string{"push", "project", "group", "api-url", "api-key"}
	for _, name := range flags {
		f := scanCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected --%s flag to be registered on scan command", name)
		}
	}

	// Verify --push defaults to false.
	pushFlag := scanCmd.Flags().Lookup("push")
	if pushFlag != nil && pushFlag.DefValue != "false" {
		t.Errorf("--push default = %q, want %q", pushFlag.DefValue, "false")
	}
}

func TestScanCommand_BadCategoryExitsConfigError(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "a.py"), []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "--category", "bogus"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid --category, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should mention the bad value: %v", err)
	}
}

func TestScanCommand_OnlyInventoryHintWhenPass2Skipped(t *testing.T) {
	// Only meaningful when opengrep is absent — otherwise pass 2 would run.
	if opengrep.NewRunner() != nil {
		t.Skip("opengrep is installed; this test requires it absent")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "a.py"), []byte("x = 1\n"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", tmpDir, "--only-inventory"})

	_ = rootCmd.Execute()

	if !strings.Contains(buf.String(), "inventory rules require Pass 2") {
		t.Errorf("expected --only-inventory hint in output, got:\n%s", buf.String())
	}
}

func TestScanCommand_MissingPathExitsConfigError(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", "/tmp/does-not-exist-" + t.Name()})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should explain missing path: %v", err)
	}
}

func TestScanCommand_NonDirectoryPathExitsConfigError(t *testing.T) {
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "a-file.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"scan", filePath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-directory path, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error should mention 'not a directory': %v", err)
	}
}
