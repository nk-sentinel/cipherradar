package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".cradar.yml")

	content := `api_url: https://cipherradar.example.com/api/v1
api_key_env: MY_API_KEY
project: payment-service
group: Engineering/Backend
default_format: cyclonedx-json
passes:
  - 1
  - 2
  - 3
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	if cfg.APIURL != "https://cipherradar.example.com/api/v1" {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, "https://cipherradar.example.com/api/v1")
	}
	if cfg.APIKeyEnv != "MY_API_KEY" {
		t.Errorf("APIKeyEnv = %q, want %q", cfg.APIKeyEnv, "MY_API_KEY")
	}
	if cfg.Project != "payment-service" {
		t.Errorf("Project = %q, want %q", cfg.Project, "payment-service")
	}
	if cfg.Group != "Engineering/Backend" {
		t.Errorf("Group = %q, want %q", cfg.Group, "Engineering/Backend")
	}
	if cfg.Format != "cyclonedx-json" {
		t.Errorf("Format = %q, want %q", cfg.Format, "cyclonedx-json")
	}
	if len(cfg.Passes) != 3 || cfg.Passes[0] != 1 || cfg.Passes[1] != 2 || cfg.Passes[2] != 3 {
		t.Errorf("Passes = %v, want [1 2 3]", cfg.Passes)
	}
}

func TestLoadConfig_NonExistentFileReturnsEmpty(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/.cradar.yml")
	if err != nil {
		t.Fatalf("LoadConfig() should not error on missing file, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig() returned nil config for missing file")
	}
	if cfg.APIURL != "" || cfg.Project != "" {
		t.Errorf("expected empty config, got APIURL=%q Project=%q", cfg.APIURL, cfg.Project)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".cradar.yml")

	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".cradar.yml")

	if err := os.WriteFile(cfgPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.APIURL != "" {
		t.Errorf("expected empty APIURL, got %q", cfg.APIURL)
	}
}

func TestLoadConfig_PartialFields(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".cradar.yml")

	content := `project: my-project
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if cfg.Project != "my-project" {
		t.Errorf("Project = %q, want %q", cfg.Project, "my-project")
	}
	if cfg.APIURL != "" {
		t.Errorf("APIURL should be empty, got %q", cfg.APIURL)
	}
	if cfg.Group != "" {
		t.Errorf("Group should be empty, got %q", cfg.Group)
	}
}

func TestResolveAPIKey_ExplicitKeyTakesPrecedence(t *testing.T) {
	cfg := &Config{APIKeyEnv: "TEST_API_KEY_VAR"}
	os.Setenv("TEST_API_KEY_VAR", "from-env")
	defer os.Unsetenv("TEST_API_KEY_VAR")

	key := cfg.ResolveAPIKey("explicit-key")
	if key != "explicit-key" {
		t.Errorf("ResolveAPIKey() = %q, want %q", key, "explicit-key")
	}
}

func TestResolveAPIKey_FallsBackToEnvVar(t *testing.T) {
	cfg := &Config{APIKeyEnv: "TEST_RESOLVE_KEY"}
	os.Setenv("TEST_RESOLVE_KEY", "env-value")
	defer os.Unsetenv("TEST_RESOLVE_KEY")

	key := cfg.ResolveAPIKey("")
	if key != "env-value" {
		t.Errorf("ResolveAPIKey() = %q, want %q", key, "env-value")
	}
}

func TestResolveAPIKey_ReturnsEmptyWhenNothingSet(t *testing.T) {
	cfg := &Config{}
	key := cfg.ResolveAPIKey("")
	if key != "" {
		t.Errorf("ResolveAPIKey() = %q, want empty", key)
	}
}
