// Package config handles loading and merging of .cradar.yml configuration files.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the contents of a .cradar.yml configuration file.
type Config struct {
	// APIURL is the portal API base URL (e.g. "https://cipherradar.company.com/api/v1").
	APIURL string `yaml:"api_url"`
	// APIKeyEnv is the name of the environment variable containing the API key.
	// If set, the API key is read from this env var instead of being stored in the file.
	APIKeyEnv string `yaml:"api_key_env"`
	// Project is the default project name for --push uploads.
	Project string `yaml:"project"`
	// Group is the default group path for --push uploads.
	Group string `yaml:"group"`
	// Format is the default output format (cyclonedx-json, sarif, text, pdf).
	Format string `yaml:"default_format"`
	// Passes is the default list of scan passes to run.
	Passes []int `yaml:"passes"`
	// CustomWrappers defines custom crypto wrapper functions to detect during scanning.
	CustomWrappers []CustomWrapper `yaml:"custom_wrappers"`
}

// CustomWrapper defines a custom cryptographic wrapper function that the
// scanner should treat as a crypto call. This allows organizations to map
// their internal wrapper libraries to CBOM asset types.
type CustomWrapper struct {
	// Name is the fully qualified function name (e.g. "mycompany.crypto.encrypt").
	Name string `yaml:"name"`
	// Language is the source language this wrapper applies to (e.g. "python", "java").
	Language string `yaml:"language"`
	// Type is the CBOM asset type (e.g. "algorithm", "protocol").
	Type string `yaml:"type"`
	// Parameters maps parameter roles to argument positions.
	// Common keys: "key", "algorithm", "mode", "iv".
	Parameters map[string]int `yaml:"parameters"`
	// Severity is the finding severity (e.g. "info", "low", "medium", "high", "critical").
	Severity string `yaml:"severity"`
}

// LoadConfig reads and parses a .cradar.yml file from the given path.
// Returns an empty Config (not an error) if the file does not exist,
// since the config file is optional.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	return &cfg, nil
}

// ResolveAPIKey returns the API key by checking (in order):
//  1. The explicit apiKey argument (from --api-key flag or CRADAR_API_KEY env)
//  2. The environment variable named in cfg.APIKeyEnv
//
// Returns empty string if no API key is available.
func (cfg *Config) ResolveAPIKey(apiKey string) string {
	if apiKey != "" {
		return apiKey
	}
	if cfg.APIKeyEnv != "" {
		return os.Getenv(cfg.APIKeyEnv)
	}
	return ""
}
