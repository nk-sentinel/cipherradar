// Package rules — SyncRules downloads custom rules from the CipherRadar portal.
package rules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// lastSyncFile stores the ISO 8601 timestamp of the last successful sync.
	lastSyncFile = ".last_sync"
	// syncTimeout is the HTTP timeout for delta sync requests.
	syncTimeout = 15 * time.Second
)

// DeltaSyncRule represents a single rule from the portal delta sync response.
type DeltaSyncRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Language    string `json:"language"`
	PatternType string `json:"patternType"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	Enabled     bool   `json:"enabled"`
	UpdatedAt   string `json:"updatedAt"`
}

// DeltaSyncResponse represents the response from GET /api/v1/rules/delta.
type DeltaSyncResponse struct {
	Items []DeltaSyncRule `json:"items"`
	Total int             `json:"total"`
}

// RulesDir returns the path to the user's cached rules directory (~/.cradar/rules/).
func RulesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory: %w", err)
	}
	return filepath.Join(home, ".cradar", "rules"), nil
}

// SyncRules downloads new/updated rules from the portal since the last sync.
// It writes YAML rule files to ~/.cradar/rules/ and updates the .last_sync timestamp.
// On any failure it returns an error but does not prevent scanning.
func SyncRules(apiURL, apiKey string) error {
	if apiURL == "" || apiKey == "" {
		return fmt.Errorf("api_url and api_key are required for rule sync")
	}

	rulesDir, err := RulesDir()
	if err != nil {
		return err
	}

	// Ensure the rules directory exists.
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return fmt.Errorf("creating rules directory %s: %w", rulesDir, err)
	}

	// Read last sync timestamp.
	since := readLastSync(rulesDir)

	// Build the request URL.
	apiURL = strings.TrimRight(apiURL, "/")
	reqURL := fmt.Sprintf("%s/rules/delta?since=%s", apiURL, since)

	client := &http.Client{Timeout: syncTimeout}
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("creating sync request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting rule delta sync: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rule delta sync returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading sync response: %w", err)
	}

	var syncResp DeltaSyncResponse
	if err := json.Unmarshal(body, &syncResp); err != nil {
		return fmt.Errorf("parsing sync response: %w", err)
	}

	// Write each rule as a YAML file.
	for _, rule := range syncResp.Items {
		if err := writeRuleFile(rulesDir, rule); err != nil {
			return fmt.Errorf("writing rule %s: %w", rule.ID, err)
		}
	}

	// Update last sync timestamp.
	now := time.Now().UTC().Format(time.RFC3339)
	if err := writeLastSync(rulesDir, now); err != nil {
		return fmt.Errorf("updating last sync timestamp: %w", err)
	}

	return nil
}

// readLastSync reads the last sync timestamp from the .last_sync file.
// Returns the epoch timestamp if the file doesn't exist.
func readLastSync(rulesDir string) string {
	path := filepath.Join(rulesDir, lastSyncFile)
	data, err := os.ReadFile(path)
	if err != nil {
		// No previous sync — use epoch.
		return "1970-01-01T00:00:00Z"
	}
	ts := strings.TrimSpace(string(data))
	if ts == "" {
		return "1970-01-01T00:00:00Z"
	}
	return ts
}

// writeLastSync writes the timestamp to the .last_sync file.
func writeLastSync(rulesDir string, timestamp string) error {
	path := filepath.Join(rulesDir, lastSyncFile)
	return os.WriteFile(path, []byte(timestamp+"\n"), 0644)
}

// writeRuleFile writes a single rule as a YAML file to the rules directory.
// The filename is based on the rule ID: <rule-id>.yml
func writeRuleFile(rulesDir string, rule DeltaSyncRule) error {
	// If the rule has a raw OpenGrep pattern, write it directly.
	if rule.PatternType == "opengrep" && rule.Pattern != "" {
		filename := sanitizeFilename(rule.ID) + ".yml"
		outPath := filepath.Join(rulesDir, filename)
		return os.WriteFile(outPath, []byte(rule.Pattern), 0644)
	}

	// For other pattern types, wrap into a minimal YAML structure.
	wrapper := map[string]interface{}{
		"rules": []map[string]interface{}{
			{
				"id":       rule.ID,
				"pattern":  rule.Pattern,
				"message":  rule.Name,
				"severity": mapSeverity(rule.Severity),
				"languages": []string{rule.Language},
			},
		},
	}

	data, err := yaml.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("marshaling rule YAML: %w", err)
	}

	filename := sanitizeFilename(rule.ID) + ".yml"
	outPath := filepath.Join(rulesDir, filename)
	return os.WriteFile(outPath, data, 0644)
}

// sanitizeFilename replaces characters that are unsafe in filenames.
func sanitizeFilename(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return r.Replace(s)
}

// mapSeverity converts CipherRadar severity to OpenGrep severity.
func mapSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "ERROR"
	case "high":
		return "WARNING"
	case "medium":
		return "WARNING"
	case "low":
		return "INFO"
	default:
		return "INFO"
	}
}
