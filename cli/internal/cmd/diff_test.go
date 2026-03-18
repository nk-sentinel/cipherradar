package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdataDiffDir returns the absolute path to the testdata/diff directory.
func testdataDiffDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../testdata/diff")
	if err != nil {
		t.Fatalf("failed to resolve testdata dir: %v", err)
	}
	return dir
}

func TestDiffCommand_TextOutput(t *testing.T) {
	dir := testdataDiffDir(t)
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"diff", beforePath, afterPath})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("diff command failed: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "Added") {
		t.Error("text output should contain 'Added' section")
	}
	if !strings.Contains(out, "Removed") {
		t.Error("text output should contain 'Removed' section")
	}
	if !strings.Contains(out, "Changed") {
		t.Error("text output should contain 'Changed' section")
	}
	if !strings.Contains(out, "PBKDF2-SHA256") {
		t.Error("text output should mention added PBKDF2-SHA256")
	}
	if !strings.Contains(out, "MD5") {
		t.Error("text output should mention removed MD5")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("text output should contain summary line")
	}
}

func TestDiffCommand_JSONOutput(t *testing.T) {
	dir := testdataDiffDir(t)
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"diff", beforePath, afterPath, "-f", "json"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("diff command failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("missing summary field in JSON output")
	}
	if summary["added"].(float64) != 1 {
		t.Errorf("summary.added = %v, want 1", summary["added"])
	}
	if summary["removed"].(float64) != 1 {
		t.Errorf("summary.removed = %v, want 1", summary["removed"])
	}
	if summary["changed"].(float64) != 3 {
		t.Errorf("summary.changed = %v, want 3", summary["changed"])
	}
}

func TestDiffCommand_OutputToFile(t *testing.T) {
	dir := testdataDiffDir(t)
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")
	outFile := filepath.Join(t.TempDir(), "diff-output.txt")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"diff", beforePath, afterPath, "-f", "text", "-o", outFile})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("diff command failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	out := string(data)

	if !strings.Contains(out, "CipherRadar CBOM Diff") {
		t.Error("output file should contain diff header")
	}
	if !strings.Contains(out, "Added") {
		t.Error("output file should contain Added section")
	}
}
