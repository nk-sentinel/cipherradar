package diff

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
)

// LoadBOM loads a CycloneDX 1.7 JSON file and returns the parsed BOM.
func LoadBOM(path string) (*output.BOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CBOM file %s: %w", path, err)
	}
	var bom output.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing CBOM JSON %s: %w", path, err)
	}
	return &bom, nil
}
