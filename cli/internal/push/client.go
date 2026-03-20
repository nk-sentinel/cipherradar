// Package push provides the HTTP client for uploading scan results
// to the CipherRadar portal.
package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// PushResponse represents the server's response to a scan upload.
type PushResponse struct {
	ScanID    string `json:"scan_id"`
	ProjectID string `json:"project_id"`
	Message   string `json:"message"`
}

// PushClient handles uploading scan results to the CipherRadar portal API.
type PushClient struct {
	apiURL     string
	apiKey     string
	httpClient *http.Client
}

// NewPushClient creates a new PushClient with the given API URL and key.
func NewPushClient(apiURL, apiKey string) *PushClient {
	return &PushClient{
		apiURL: strings.TrimRight(apiURL, "/"),
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// UploadScanResult uploads a scan result as CycloneDX JSON to the portal.
// projectName is required. groupPath, branch, and commitSHA are optional.
func (c *PushClient) UploadScanResult(result *types.ScanResult, projectName, groupPath, branch, commitSHA string) (*PushResponse, error) {
	if projectName == "" {
		return nil, fmt.Errorf("project name is required for push")
	}

	// Convert the scan result to CycloneDX JSON.
	bom := output.ConvertScanResult(result)
	body, err := json.Marshal(bom)
	if err != nil {
		return nil, fmt.Errorf("marshaling CycloneDX JSON: %w", err)
	}

	// Build the upload URL.
	uploadURL := c.apiURL + "/scans/upload"

	req, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating upload request: %w", err)
	}

	// Set headers per ADR-025.
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-CipherRadar-Project", projectName)
	if groupPath != "" {
		req.Header.Set("X-CipherRadar-Group", groupPath)
	}
	if branch != "" {
		req.Header.Set("X-CipherRadar-Branch", branch)
	}
	if commitSHA != "" {
		req.Header.Set("X-CipherRadar-Commit", commitSHA)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("uploading scan result: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		var pushResp PushResponse
		if err := json.Unmarshal(respBody, &pushResp); err != nil {
			return nil, fmt.Errorf("parsing upload response: %w", err)
		}
		return &pushResp, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication failed: invalid or missing API key")
	case http.StatusNotFound:
		return nil, fmt.Errorf("project %q not found and insufficient permissions to create it", projectName)
	case http.StatusUnprocessableEntity:
		return nil, fmt.Errorf("server rejected the CBOM: %s", string(respBody))
	default:
		return nil, fmt.Errorf("upload failed with HTTP %d: %s", resp.StatusCode, string(respBody))
	}
}
