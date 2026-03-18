package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadPolicy loads a policy configuration from a YAML file.
func LoadPolicy(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}

	var config PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing policy file %s: %w", path, err)
	}

	return &config, nil
}
