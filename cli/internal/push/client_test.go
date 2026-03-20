package push

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func testScanResult() *types.ScanResult {
	return &types.ScanResult{
		Target: "/tmp/test-project",
		Findings: []types.Finding{
			{
				ID:     "finding-1",
				Name:   "AES-256-GCM",
				RuleID: "cbom-go-aes-newcipher",
			},
		},
		StartTime:    time.Now().Add(-5 * time.Second),
		EndTime:      time.Now(),
		PassesRun:    []int{1},
		FilesScanned: 10,
	}
}

func TestUploadScanResult_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/scans/upload") {
			t.Errorf("expected path ending in /scans/upload, got %s", r.URL.Path)
		}

		// Verify headers.
		if r.Header.Get("Content-Type") != "application/vnd.cyclonedx+json" {
			t.Errorf("Content-Type = %q, want application/vnd.cyclonedx+json", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Authorization = %q, want Bearer test-api-key", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-CipherRadar-Project") != "my-project" {
			t.Errorf("X-CipherRadar-Project = %q, want my-project", r.Header.Get("X-CipherRadar-Project"))
		}
		if r.Header.Get("X-CipherRadar-Group") != "Engineering/Backend" {
			t.Errorf("X-CipherRadar-Group = %q, want Engineering/Backend", r.Header.Get("X-CipherRadar-Group"))
		}
		if r.Header.Get("X-CipherRadar-Branch") != "main" {
			t.Errorf("X-CipherRadar-Branch = %q, want main", r.Header.Get("X-CipherRadar-Branch"))
		}
		if r.Header.Get("X-CipherRadar-Commit") != "abc123" {
			t.Errorf("X-CipherRadar-Commit = %q, want abc123", r.Header.Get("X-CipherRadar-Commit"))
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(PushResponse{
			ScanID:    "scan-001",
			ProjectID: "proj-001",
			Message:   "Scan uploaded successfully",
		})
	}))
	defer server.Close()

	client := NewPushClient(server.URL+"/api/v1", "test-api-key")
	resp, err := client.UploadScanResult(testScanResult(), "my-project", "Engineering/Backend", "main", "abc123")
	if err != nil {
		t.Fatalf("UploadScanResult() error: %v", err)
	}
	if resp.ScanID != "scan-001" {
		t.Errorf("ScanID = %q, want scan-001", resp.ScanID)
	}
	if resp.ProjectID != "proj-001" {
		t.Errorf("ProjectID = %q, want proj-001", resp.ProjectID)
	}
}

func TestUploadScanResult_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer server.Close()

	client := NewPushClient(server.URL+"/api/v1", "bad-key")
	_, err := client.UploadScanResult(testScanResult(), "my-project", "", "", "")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error = %q, want to contain 'authentication failed'", err.Error())
	}
}

func TestUploadScanResult_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"project not found"}`))
	}))
	defer server.Close()

	client := NewPushClient(server.URL+"/api/v1", "test-key")
	_, err := client.UploadScanResult(testScanResult(), "nonexistent-project", "", "", "")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want to contain 'not found'", err.Error())
	}
}

func TestUploadScanResult_UnprocessableEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":"invalid CBOM schema"}`))
	}))
	defer server.Close()

	client := NewPushClient(server.URL+"/api/v1", "test-key")
	_, err := client.UploadScanResult(testScanResult(), "my-project", "", "", "")
	if err == nil {
		t.Fatal("expected error for 422 response")
	}
	if !strings.Contains(err.Error(), "server rejected") {
		t.Errorf("error = %q, want to contain 'server rejected'", err.Error())
	}
}

func TestUploadScanResult_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal server error`))
	}))
	defer server.Close()

	client := NewPushClient(server.URL+"/api/v1", "test-key")
	_, err := client.UploadScanResult(testScanResult(), "my-project", "", "", "")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain '500'", err.Error())
	}
}

func TestUploadScanResult_MissingProjectName(t *testing.T) {
	client := NewPushClient("http://localhost", "test-key")
	_, err := client.UploadScanResult(testScanResult(), "", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty project name")
	}
	if !strings.Contains(err.Error(), "project name is required") {
		t.Errorf("error = %q, want to contain 'project name is required'", err.Error())
	}
}

func TestUploadScanResult_OptionalHeadersOmittedWhenEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify optional headers are absent when not provided.
		if r.Header.Get("X-CipherRadar-Group") != "" {
			t.Errorf("expected empty X-CipherRadar-Group header, got %q", r.Header.Get("X-CipherRadar-Group"))
		}
		if r.Header.Get("X-CipherRadar-Branch") != "" {
			t.Errorf("expected empty X-CipherRadar-Branch header, got %q", r.Header.Get("X-CipherRadar-Branch"))
		}
		if r.Header.Get("X-CipherRadar-Commit") != "" {
			t.Errorf("expected empty X-CipherRadar-Commit header, got %q", r.Header.Get("X-CipherRadar-Commit"))
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(PushResponse{ScanID: "scan-002", ProjectID: "proj-002"})
	}))
	defer server.Close()

	client := NewPushClient(server.URL+"/api/v1", "test-key")
	_, err := client.UploadScanResult(testScanResult(), "my-project", "", "", "")
	if err != nil {
		t.Fatalf("UploadScanResult() error: %v", err)
	}
}

func TestNewPushClient_TrailingSlashTrimmed(t *testing.T) {
	client := NewPushClient("https://example.com/api/v1/", "key")
	if strings.HasSuffix(client.apiURL, "/") {
		t.Errorf("apiURL should not have trailing slash, got %q", client.apiURL)
	}
}
