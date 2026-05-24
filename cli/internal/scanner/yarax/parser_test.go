package yarax

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// loadFixture returns the contents of testdata/<name>. Fails the test on
// any IO error so callers can use the return value directly.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return b
}

func TestParse_EmptyOutput(t *testing.T) {
	// Wholly empty input — return (nil, nil) without erroring.
	findings, err := ParseResults(nil, "/anywhere")
	if err != nil {
		t.Errorf("expected nil error for empty input, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}

	// Whitespace-only input — same.
	findings, err = ParseResults([]byte("   \n  \t  "), "/anywhere")
	if err != nil {
		t.Errorf("expected nil error for whitespace input, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for whitespace input, got %v", findings)
	}
}

func TestParse_NoMatches(t *testing.T) {
	data := loadFixture(t, "no-matches.json")
	findings, err := ParseResults(data, "/anywhere")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for matches=[], got %v", findings)
	}
}

func TestParse_SingleMatch(t *testing.T) {
	data := loadFixture(t, "single-match.json")
	findings, err := ParseResults(data, "/fallback")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.RuleID != "probe_openssl_3_0" {
		t.Errorf("RuleID: expected %q, got %q", "probe_openssl_3_0", f.RuleID)
	}
	if f.Pass != 3 {
		t.Errorf("Pass: expected 3, got %d", f.Pass)
	}
	if f.AssetType != types.AssetAlgorithm {
		t.Errorf("AssetType: expected %q, got %q", types.AssetAlgorithm, f.AssetType)
	}
	if f.Severity != types.SeverityInfo {
		t.Errorf("Severity: expected %q, got %q", types.SeverityInfo, f.Severity)
	}
	if f.Confidence != types.ConfidenceMedium {
		t.Errorf("Confidence: expected %q, got %q", types.ConfidenceMedium, f.Confidence)
	}
	if f.Name != "probe_openssl_3_0" {
		t.Errorf("Name: expected %q, got %q", "probe_openssl_3_0", f.Name)
	}
	if f.Description != "Probe rule for Sub-PR A development" {
		t.Errorf("Description: expected meta.description; got %q", f.Description)
	}
	if f.Location.File != "/home/test/openssl-versions" {
		t.Errorf("Location.File: expected %q, got %q", "/home/test/openssl-versions", f.Location.File)
	}
	if f.Location.StartCol != 8222 {
		t.Errorf("Location.StartCol (offset): expected 8222, got %d", f.Location.StartCol)
	}
	if f.Location.EndCol != 8222 {
		t.Errorf("Location.EndCol: expected 8222, got %d", f.Location.EndCol)
	}
	if f.Location.Snippet == "" {
		t.Error("Location.Snippet: expected non-empty snippet")
	}
}

func TestParse_MinimalMatchUsesFallbackTarget(t *testing.T) {
	// When a match arrives with no `file` (defensive — not seen in
	// 1.14.0 today), the runner's fallback target populates the
	// location.
	data := loadFixture(t, "minimal-match.json")
	findings, err := ParseResults(data, "/runner-fallback")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	// Match emits its own file in this fixture, so the explicit file
	// wins over the fallback. Verify the parser respects that.
	if f.Location.File != "/home/test/sample" {
		t.Errorf("expected explicit file to win, got %q", f.Location.File)
	}
	// Without strings the offset must degrade to 0, and the
	// description falls back to the rule-name template since meta is
	// absent.
	if f.Location.StartCol != 0 {
		t.Errorf("expected offset 0 when no strings present, got %d", f.Location.StartCol)
	}
	if f.Description != `YARA-X rule "probe_minimal" matched` {
		t.Errorf("unexpected description: %q", f.Description)
	}
}

func TestParse_FallbackTargetWhenFileMissing(t *testing.T) {
	// Build the payload inline rather than as a fixture so we can
	// exercise the "no file in match" path explicitly.
	payload := []byte(`{"version":"1.14.0","matches":[{"rule":"r1"}]}`)
	findings, err := ParseResults(payload, "/runner-fallback")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := findings[0].Location.File; got != "/runner-fallback" {
		t.Errorf("expected fallback target, got %q", got)
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	_, err := ParseResults([]byte("{not json"), "/anywhere")
	if err == nil {
		t.Error("expected error on malformed JSON")
	}
}
