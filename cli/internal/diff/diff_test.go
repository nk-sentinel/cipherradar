package diff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
)

// testdataDir returns the path to the testdata/diff directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	// Walk up from internal/diff to cli root.
	dir, err := filepath.Abs("../../testdata/diff")
	if err != nil {
		t.Fatalf("failed to resolve testdata dir: %v", err)
	}
	return dir
}

// makeComponent is a test helper to build a component quickly.
func makeComponent(bomRef, name, description string, assetType string, algProps *cyclonedx17.AlgorithmProperties, protoProps *cyclonedx17.ProtocolProperties, location string, line int) output.Component {
	c := output.Component{
		Type:        "cryptographic-asset",
		BOMRef:      bomRef,
		Name:        name,
		Description: description,
		CryptoProperties: &cyclonedx17.CryptoProperties{
			AssetType:          assetType,
			AlgorithmProperties: algProps,
			ProtocolProperties:  protoProps,
		},
	}
	if location != "" {
		c.Evidence = &output.Evidence{
			Occurrences: []output.Occurrence{
				{Location: location, Line: line},
			},
		}
	}
	return c
}

func makeBOM(components ...output.Component) *output.BOM {
	return &output.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.7",
		Version:     1,
		Components:  components,
	}
}

func TestCompareBOMs_Identifies_Added(t *testing.T) {
	before := makeBOM(
		makeComponent("FIND-001", "SHA-256", "SHA-256 hash", "algorithm",
			&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "sha2"},
			nil, "crypto/hash.py", 10),
	)
	after := makeBOM(
		makeComponent("FIND-001", "SHA-256", "SHA-256 hash", "algorithm",
			&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "sha2"},
			nil, "crypto/hash.py", 10),
		makeComponent("FIND-002", "AES-256-GCM", "AES-256-GCM encryption", "algorithm",
			&cyclonedx17.AlgorithmProperties{Primitive: "ae", AlgorithmFamily: "aes", Mode: "gcm"},
			nil, "crypto/enc.py", 15),
	)

	result := CompareBOMs(before, after)

	if len(result.Added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(result.Added))
	}
	if result.Added[0].Name != "AES-256-GCM" {
		t.Errorf("added component name = %q, want AES-256-GCM", result.Added[0].Name)
	}
}

func TestCompareBOMs_Identifies_Removed(t *testing.T) {
	before := makeBOM(
		makeComponent("FIND-001", "MD5", "MD5 hash", "algorithm",
			&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "md5"},
			nil, "crypto/legacy.py", 8),
		makeComponent("FIND-002", "SHA-256", "SHA-256 hash", "algorithm",
			&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "sha2"},
			nil, "crypto/hash.py", 10),
	)
	after := makeBOM(
		makeComponent("FIND-002", "SHA-256", "SHA-256 hash", "algorithm",
			&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "sha2"},
			nil, "crypto/hash.py", 10),
	)

	result := CompareBOMs(before, after)

	if len(result.Removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(result.Removed))
	}
	if result.Removed[0].Name != "MD5" {
		t.Errorf("removed component name = %q, want MD5", result.Removed[0].Name)
	}
}

func TestCompareBOMs_Identifies_Changed(t *testing.T) {
	before := makeBOM(
		makeComponent("FIND-003", "RSA-2048", "RSA-2048 key gen", "algorithm",
			&cyclonedx17.AlgorithmProperties{
				Primitive:              "pke",
				AlgorithmFamily:        "rsa",
				ClassicalSecurityLevel: 2048,
			},
			nil, "keys/generate.py", 5),
	)
	after := makeBOM(
		makeComponent("FIND-003", "RSA-4096", "RSA-4096 key gen", "algorithm",
			&cyclonedx17.AlgorithmProperties{
				Primitive:              "pke",
				AlgorithmFamily:        "rsa",
				ClassicalSecurityLevel: 4096,
			},
			nil, "keys/generate.py", 5),
	)

	result := CompareBOMs(before, after)

	if len(result.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(result.Changed))
	}
	cc := result.Changed[0]
	if cc.Name != "RSA-2048" {
		t.Errorf("changed component name = %q, want RSA-2048", cc.Name)
	}

	// Check specific changes are listed.
	foundNameChange := false
	foundKeySizeChange := false
	for _, change := range cc.Changes {
		if strings.Contains(change, "Name:") && strings.Contains(change, "RSA-2048") && strings.Contains(change, "RSA-4096") {
			foundNameChange = true
		}
		if strings.Contains(change, "Key size:") && strings.Contains(change, "2048") && strings.Contains(change, "4096") {
			foundKeySizeChange = true
		}
	}
	if !foundNameChange {
		t.Error("expected name change to be listed in changes")
	}
	if !foundKeySizeChange {
		t.Error("expected key size change to be listed in changes")
	}
}

func TestCompareBOMs_Counts_Unchanged(t *testing.T) {
	comp := makeComponent("FIND-001", "SHA-256", "SHA-256 hash", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "sha2", ClassicalSecurityLevel: 128},
		nil, "crypto/hash.py", 10)

	before := makeBOM(comp)
	after := makeBOM(comp)

	result := CompareBOMs(before, after)

	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(result.Removed))
	}
	if len(result.Changed) != 0 {
		t.Errorf("expected 0 changed, got %d", len(result.Changed))
	}
}

func TestCompareBOMs_Identical_BOMs(t *testing.T) {
	c1 := makeComponent("FIND-001", "SHA-256", "SHA-256 hash", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "hash", AlgorithmFamily: "sha2"},
		nil, "crypto/hash.py", 10)
	c2 := makeComponent("FIND-002", "AES-128-CBC", "AES encryption", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "block-cipher", AlgorithmFamily: "aes", Mode: "cbc"},
		nil, "crypto/enc.py", 20)

	before := makeBOM(c1, c2)
	after := makeBOM(c1, c2)

	result := CompareBOMs(before, after)

	if result.Unchanged != 2 {
		t.Errorf("expected 2 unchanged, got %d", result.Unchanged)
	}
	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Errorf("expected no adds/removes/changes for identical BOMs, got +%d -%d ~%d",
			len(result.Added), len(result.Removed), len(result.Changed))
	}
}

func TestCompareBOMs_Empty_Before_All_Added(t *testing.T) {
	c1 := makeComponent("FIND-001", "SHA-256", "SHA-256 hash", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "hash"},
		nil, "crypto/hash.py", 10)
	c2 := makeComponent("FIND-002", "AES-256", "AES encryption", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "block-cipher"},
		nil, "crypto/enc.py", 20)

	before := makeBOM()
	after := makeBOM(c1, c2)

	result := CompareBOMs(before, after)

	if len(result.Added) != 2 {
		t.Errorf("expected 2 added, got %d", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(result.Removed))
	}
	if result.Unchanged != 0 {
		t.Errorf("expected 0 unchanged, got %d", result.Unchanged)
	}
}

func TestCompareBOMs_Empty_After_All_Removed(t *testing.T) {
	c1 := makeComponent("FIND-001", "SHA-256", "SHA-256 hash", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "hash"},
		nil, "crypto/hash.py", 10)
	c2 := makeComponent("FIND-002", "AES-256", "AES encryption", "algorithm",
		&cyclonedx17.AlgorithmProperties{Primitive: "block-cipher"},
		nil, "crypto/enc.py", 20)

	before := makeBOM(c1, c2)
	after := makeBOM()

	result := CompareBOMs(before, after)

	if len(result.Removed) != 2 {
		t.Errorf("expected 2 removed, got %d", len(result.Removed))
	}
	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d", len(result.Added))
	}
	if result.Unchanged != 0 {
		t.Errorf("expected 0 unchanged, got %d", result.Unchanged)
	}
}

func TestCompareBOMs_MatchByNameAndLocation(t *testing.T) {
	// Components without bom-ref should match by name + location.
	before := makeBOM(output.Component{
		Type:        "cryptographic-asset",
		Name:        "AES-128",
		Description: "AES encryption",
		CryptoProperties: &cyclonedx17.CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &cyclonedx17.AlgorithmProperties{
				Primitive:              "block-cipher",
				ClassicalSecurityLevel: 128,
			},
		},
		Evidence: &output.Evidence{
			Occurrences: []output.Occurrence{{Location: "crypto/enc.py", Line: 10}},
		},
	})
	after := makeBOM(output.Component{
		Type:        "cryptographic-asset",
		Name:        "AES-128",
		Description: "AES encryption updated",
		CryptoProperties: &cyclonedx17.CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &cyclonedx17.AlgorithmProperties{
				Primitive:              "block-cipher",
				ClassicalSecurityLevel: 128,
			},
		},
		Evidence: &output.Evidence{
			Occurrences: []output.Occurrence{{Location: "crypto/enc.py", Line: 10}},
		},
	})

	result := CompareBOMs(before, after)

	if len(result.Changed) != 1 {
		t.Fatalf("expected 1 changed (matched by name+location), got %d", len(result.Changed))
	}
	if result.Unchanged != 0 {
		t.Errorf("expected 0 unchanged, got %d", result.Unchanged)
	}
}

func TestFormatText_ProducesExpectedOutput(t *testing.T) {
	result := &DiffResult{
		Before: "before.json",
		After:  "after.json",
		Added: []output.Component{
			makeComponent("FIND-006", "PBKDF2-SHA256", "PBKDF2 KDF", "algorithm",
				&cyclonedx17.AlgorithmProperties{Primitive: "kdf"},
				nil, "auth/password.py", 22),
		},
		Removed: []output.Component{
			makeComponent("FIND-001", "MD5", "MD5 hash", "algorithm",
				&cyclonedx17.AlgorithmProperties{Primitive: "hash"},
				nil, "crypto/legacy.py", 8),
		},
		Changed: []ChangedComponent{
			{
				BOMRef: "FIND-003",
				Name:   "RSA-2048",
				Before: makeComponent("FIND-003", "RSA-2048", "RSA-2048", "algorithm",
					&cyclonedx17.AlgorithmProperties{ClassicalSecurityLevel: 2048},
					nil, "keys/generate.py", 5),
				After: makeComponent("FIND-003", "RSA-4096", "RSA-4096", "algorithm",
					&cyclonedx17.AlgorithmProperties{ClassicalSecurityLevel: 4096},
					nil, "keys/generate.py", 5),
				Changes: []string{"Name: RSA-2048 \u2192 RSA-4096", "Key size: 2048 \u2192 4096"},
			},
		},
		Unchanged: 1,
	}

	var buf bytes.Buffer
	err := FormatText(&buf, result)
	if err != nil {
		t.Fatalf("FormatText failed: %v", err)
	}

	out := buf.String()

	// Verify structure.
	if !strings.Contains(out, "CipherRadar CBOM Diff") {
		t.Error("output should contain header")
	}
	if !strings.Contains(out, "Before: before.json") {
		t.Error("output should contain before filename")
	}
	if !strings.Contains(out, "After:  after.json") {
		t.Error("output should contain after filename")
	}
	if !strings.Contains(out, "Added (1):") {
		t.Error("output should contain Added section")
	}
	if !strings.Contains(out, "PBKDF2-SHA256") {
		t.Error("output should contain added component name")
	}
	if !strings.Contains(out, "Removed (1):") {
		t.Error("output should contain Removed section")
	}
	if !strings.Contains(out, "MD5") {
		t.Error("output should contain removed component name")
	}
	if !strings.Contains(out, "Changed (1):") {
		t.Error("output should contain Changed section")
	}
	if !strings.Contains(out, "Unchanged: 1") {
		t.Error("output should contain unchanged count")
	}
	if !strings.Contains(out, "Summary: +1 added, -1 removed, ~1 changed, =1 unchanged") {
		t.Errorf("output should contain summary line, got:\n%s", out)
	}
}

func TestFormatJSON_ProducesValidJSON(t *testing.T) {
	result := &DiffResult{
		Before: "before.json",
		After:  "after.json",
		Added: []output.Component{
			makeComponent("FIND-006", "PBKDF2-SHA256", "PBKDF2 KDF", "algorithm",
				&cyclonedx17.AlgorithmProperties{Primitive: "kdf"},
				nil, "auth/password.py", 22),
		},
		Removed: []output.Component{
			makeComponent("FIND-001", "MD5", "MD5 hash", "algorithm",
				&cyclonedx17.AlgorithmProperties{Primitive: "hash"},
				nil, "crypto/legacy.py", 8),
		},
		Changed: []ChangedComponent{
			{
				BOMRef:  "FIND-003",
				Name:    "RSA-2048",
				Changes: []string{"Key size: 2048 \u2192 4096"},
			},
		},
		Unchanged: 2,
	}

	var buf bytes.Buffer
	err := FormatJSON(&buf, result)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}

	// Check summary counts.
	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid summary field")
	}
	if summary["added"].(float64) != 1 {
		t.Errorf("summary.added = %v, want 1", summary["added"])
	}
	if summary["removed"].(float64) != 1 {
		t.Errorf("summary.removed = %v, want 1", summary["removed"])
	}
	if summary["changed"].(float64) != 1 {
		t.Errorf("summary.changed = %v, want 1", summary["changed"])
	}
	if summary["unchanged"].(float64) != 2 {
		t.Errorf("summary.unchanged = %v, want 2", summary["unchanged"])
	}

	// Check arrays are present.
	added, ok := parsed["added"].([]interface{})
	if !ok || len(added) != 1 {
		t.Error("expected 1 added component in JSON")
	}
	removed, ok := parsed["removed"].([]interface{})
	if !ok || len(removed) != 1 {
		t.Error("expected 1 removed component in JSON")
	}
	changed, ok := parsed["changed"].([]interface{})
	if !ok || len(changed) != 1 {
		t.Error("expected 1 changed component in JSON")
	}
}

func TestLoadBOM_ValidFile(t *testing.T) {
	dir := testdataDir(t)
	bom, err := LoadBOM(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatalf("LoadBOM failed: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.7" {
		t.Errorf("specVersion = %q, want 1.7", bom.SpecVersion)
	}
	if len(bom.Components) != 5 {
		t.Errorf("expected 5 components, got %d", len(bom.Components))
	}
}

func TestLoadBOM_InvalidFile(t *testing.T) {
	// Non-existent file.
	_, err := LoadBOM("/nonexistent/path/cbom.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}

	// Invalid JSON.
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmpFile, []byte("not json at all"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	_, err = LoadBOM(tmpFile)
	if err == nil {
		t.Error("expected error for invalid JSON file")
	}
}

func TestCompareBOMs_FullFixtures(t *testing.T) {
	dir := testdataDir(t)
	before, err := LoadBOM(filepath.Join(dir, "before.json"))
	if err != nil {
		t.Fatalf("loading before.json: %v", err)
	}
	after, err := LoadBOM(filepath.Join(dir, "after.json"))
	if err != nil {
		t.Fatalf("loading after.json: %v", err)
	}

	result := CompareBOMs(before, after)

	// MD5 (FIND-001) removed.
	if len(result.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(result.Removed))
	} else if result.Removed[0].Name != "MD5" {
		t.Errorf("expected removed component to be MD5, got %q", result.Removed[0].Name)
	}

	// PBKDF2-SHA256 (FIND-006) added.
	if len(result.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(result.Added))
	} else if result.Added[0].Name != "PBKDF2-SHA256" {
		t.Errorf("expected added component to be PBKDF2-SHA256, got %q", result.Added[0].Name)
	}

	// RSA, AES, TLS changed (FIND-003, FIND-004, FIND-005).
	if len(result.Changed) != 3 {
		t.Errorf("expected 3 changed, got %d", len(result.Changed))
	}

	// SHA-256 (FIND-002) unchanged.
	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.Unchanged)
	}
}
