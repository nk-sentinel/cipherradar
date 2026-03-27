package rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// syncRulesWithDir is a test helper that runs the sync logic against a specific
// directory, avoiding writes to the user's real ~/.cradar/rules/.
func syncRulesWithDir(apiURL, apiKey, dir string) error {
	if apiURL == "" || apiKey == "" {
		return fmt.Errorf("api_url and api_key are required for rule sync")
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	since := readLastSync(dir)
	apiURL = strings.TrimRight(apiURL, "/")
	reqURL := apiURL + "/rules/delta?since=" + since

	client := &http.Client{Timeout: syncTimeout}
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rule delta sync returned HTTP %d", resp.StatusCode)
	}

	var syncResp DeltaSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return err
	}

	for _, rule := range syncResp.Items {
		if err := writeRuleFile(dir, rule); err != nil {
			return err
		}
	}

	now := "2026-03-27T12:00:00Z"
	return writeLastSync(dir, now)
}

func TestSyncDownloadsRules(t *testing.T) {
	// Set up a mock server that returns two rules.
	deltaRules := DeltaSyncResponse{
		Items: []DeltaSyncRule{
			{
				ID:          "custom-python-md5",
				Name:        "Python MD5 usage",
				Language:    "python",
				PatternType: "opengrep",
				Pattern:     "rules:\n  - id: custom-python-md5\n    pattern: hashlib.md5(...)\n    message: MD5 is broken\n    severity: WARNING",
				Severity:    "high",
				Enabled:     true,
				UpdatedAt:   "2026-03-27T10:00:00Z",
			},
			{
				ID:          "custom-java-des",
				Name:        "Java DES usage",
				Language:    "java",
				PatternType: "regex",
				Pattern:     "Cipher\\.getInstance\\(\"DES\"\\)",
				Severity:    "critical",
				Enabled:     true,
				UpdatedAt:   "2026-03-27T11:00:00Z",
			},
		},
		Total: 2,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request.
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/rules/delta") {
			t.Errorf("expected path containing /rules/delta, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Authorization = %q, want Bearer test-api-key", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("since") == "" {
			t.Error("expected 'since' query parameter")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(deltaRules)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	err := syncRulesWithDir(server.URL+"/api/v1", "test-api-key", tmpDir)
	if err != nil {
		t.Fatalf("syncRulesWithDir() error: %v", err)
	}

	// Verify rule files were created.
	file1 := filepath.Join(tmpDir, "custom-python-md5.yml")
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("expected rule file %s to exist", file1)
	}

	file2 := filepath.Join(tmpDir, "custom-java-des.yml")
	if _, err := os.Stat(file2); os.IsNotExist(err) {
		t.Errorf("expected rule file %s to exist", file2)
	}

	// Verify the OpenGrep rule has the exact pattern content.
	content1, err := os.ReadFile(file1)
	if err != nil {
		t.Fatalf("reading rule file: %v", err)
	}
	if !strings.Contains(string(content1), "custom-python-md5") {
		t.Errorf("rule file content does not contain rule ID: %s", string(content1))
	}

	// Verify .last_sync was written.
	syncFile := filepath.Join(tmpDir, ".last_sync")
	if _, err := os.Stat(syncFile); os.IsNotExist(err) {
		t.Error("expected .last_sync file to exist")
	}
	syncContent, _ := os.ReadFile(syncFile)
	ts := strings.TrimSpace(string(syncContent))
	if ts == "" || ts == "1970-01-01T00:00:00Z" {
		t.Errorf(".last_sync should contain a recent timestamp, got %q", ts)
	}
}

func TestSyncGracefulOnFailure(t *testing.T) {
	// Set up a mock server that returns 500.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	err := syncRulesWithDir(server.URL+"/api/v1", "test-api-key", tmpDir)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain '500'", err.Error())
	}

	// Verify no .last_sync file was created (failure means no update).
	syncFile := filepath.Join(tmpDir, ".last_sync")
	if _, statErr := os.Stat(syncFile); !os.IsNotExist(statErr) {
		t.Error(".last_sync should not exist after failed sync")
	}
}

func TestSyncSkippedWithoutConfig(t *testing.T) {
	// Empty apiURL should return an error.
	err := SyncRules("", "some-key")
	if err == nil {
		t.Fatal("expected error when apiURL is empty")
	}
	if !strings.Contains(err.Error(), "api_url and api_key are required") {
		t.Errorf("error = %q, want to contain 'api_url and api_key are required'", err.Error())
	}

	// Empty apiKey should return an error.
	err = SyncRules("https://example.com/api/v1", "")
	if err == nil {
		t.Fatal("expected error when apiKey is empty")
	}
	if !strings.Contains(err.Error(), "api_url and api_key are required") {
		t.Errorf("error = %q, want to contain 'api_url and api_key are required'", err.Error())
	}
}

func TestReadLastSync_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	ts := readLastSync(tmpDir)
	if ts != "1970-01-01T00:00:00Z" {
		t.Errorf("readLastSync with no file = %q, want epoch", ts)
	}
}

func TestReadLastSync_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, lastSyncFile)
	os.WriteFile(path, []byte("2026-03-27T10:00:00Z\n"), 0644)

	ts := readLastSync(tmpDir)
	if ts != "2026-03-27T10:00:00Z" {
		t.Errorf("readLastSync = %q, want 2026-03-27T10:00:00Z", ts)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple-rule", "simple-rule"},
		{"org/rule-name", "org_rule-name"},
		{"with spaces", "with_spaces"},
		{"path\\backslash", "path_backslash"},
		{"colon:name", "colon_name"},
	}
	for _, tt := range tests {
		got := sanitizeFilename(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "ERROR"},
		{"high", "WARNING"},
		{"medium", "WARNING"},
		{"low", "INFO"},
		{"unknown", "INFO"},
	}
	for _, tt := range tests {
		got := mapSeverity(tt.input)
		if got != tt.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
