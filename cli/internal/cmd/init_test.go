package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit_CreatesBothFiles(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"init", "--dir", dir})
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	for _, name := range []string{".cradar.yml", "policy.cradar.yml"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if len(data) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestInit_RefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, ".cradar.yml")
	if err := os.WriteFile(existing, []byte("# user config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"init", "--dir", dir})
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when file exists")
	}
	// Error must carry ExitConfig so CI pipelines distinguish it from
	// "findings above threshold".
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig (%d), got %d", ExitConfig, ee.Code)
	}

	// Preserve the user's original content.
	data, _ := os.ReadFile(existing)
	if !strings.Contains(string(data), "# user config") {
		t.Errorf("user file was overwritten: %q", string(data))
	}
}

func TestInit_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, ".cradar.yml")
	if err := os.WriteFile(existing, []byte("# stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"init", "--dir", dir, "--force"})
	defer func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	data, _ := os.ReadFile(existing)
	if strings.Contains(string(data), "# stale") {
		t.Errorf("--force did not overwrite")
	}
	if !strings.Contains(string(data), "CipherRadar CLI configuration") {
		t.Errorf("template header missing after overwrite: %q", firstN(string(data), 80))
	}
}
