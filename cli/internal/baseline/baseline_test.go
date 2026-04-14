package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func mkFinding(ruleID, fp string, cat types.Category) types.Finding {
	return types.Finding{
		RuleID:      ruleID,
		Name:        ruleID,
		Fingerprint: fp,
		Category:    cat,
	}
}

func TestLoad_MissingFileReturnsNilNil(t *testing.T) {
	b, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing file should not error; got %v", err)
	}
	if b != nil {
		t.Fatalf("missing file should return nil baseline; got %+v", b)
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFile)

	b := New("1.2.3")
	b.Fingerprints = []string{"fp-b", "fp-a", "fp-c"}
	b.fingerprintSet = map[string]struct{}{
		"fp-a": {}, "fp-b": {}, "fp-c": {},
	}

	if err := Save(path, b); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil baseline for existing file")
	}
	if got.Version != SchemaVersion {
		t.Errorf("Version = %d, want %d", got.Version, SchemaVersion)
	}
	if got.CradarVersion != "1.2.3" {
		t.Errorf("CradarVersion = %q, want 1.2.3", got.CradarVersion)
	}
	// Save must have sorted the slice for deterministic diffs.
	want := []string{"fp-a", "fp-b", "fp-c"}
	if !reflect.DeepEqual(got.Fingerprints, want) {
		t.Errorf("Fingerprints = %v, want %v (sorted)", got.Fingerprints, want)
	}
	for _, fp := range want {
		if !got.Contains(fp) {
			t.Errorf("Contains(%q) = false, want true", fp)
		}
	}
}

func TestSave_DoesNotMutateInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFile)

	b := New("1.0.0")
	b.Fingerprints = []string{"z", "a", "m"}
	snapshot := append([]string(nil), b.Fingerprints...)

	if err := Save(path, b); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !reflect.DeepEqual(b.Fingerprints, snapshot) {
		t.Errorf("Save mutated input: got %v, want %v", b.Fingerprints, snapshot)
	}
}

func TestLoad_RejectsFutureSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFile)

	raw := map[string]any{
		"version":        SchemaVersion + 1,
		"created":        "2026-04-14T00:00:00Z",
		"cradar_version": "99.0.0",
		"fingerprints":   []string{"fp-x"},
	}
	data, _ := json.Marshal(raw)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatalf("Load should reject future schema version")
	}
}

func TestLoad_MalformedJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should surface parse errors")
	}
}

func TestContains_NilBaselineAndEmptyFingerprint(t *testing.T) {
	var b *Baseline
	if b.Contains("anything") {
		t.Error("nil baseline must never Contains")
	}
	b2 := New("1.0.0")
	if b2.Contains("") {
		t.Error("empty fingerprint must never match")
	}
}

func TestApply_NilBaselineKeepsAll(t *testing.T) {
	findings := []types.Finding{
		mkFinding("r1", "fp1", types.CategorySecurity),
		mkFinding("r2", "fp2", types.CategoryInventory),
	}
	res := Apply(findings, nil)
	if len(res.Kept) != 2 || res.SuppressedCount != 0 || len(res.Stale) != 0 {
		t.Errorf("nil baseline no-op failed: %+v", res)
	}
}

func TestApply_SuppressesMatchingSecurityFindings(t *testing.T) {
	b := New("1.0.0")
	b.Fingerprints = []string{"fp-sec-1"}
	b.fingerprintSet = map[string]struct{}{"fp-sec-1": {}}

	findings := []types.Finding{
		mkFinding("r-sec-1", "fp-sec-1", types.CategorySecurity),
		mkFinding("r-sec-2", "fp-sec-2", types.CategorySecurity),
	}
	res := Apply(findings, b)
	if len(res.Kept) != 1 || res.Kept[0].RuleID != "r-sec-2" {
		t.Errorf("kept = %+v, want only r-sec-2", res.Kept)
	}
	if res.SuppressedCount != 1 {
		t.Errorf("SuppressedCount = %d, want 1", res.SuppressedCount)
	}
	if len(res.Stale) != 0 {
		t.Errorf("Stale = %v, want empty", res.Stale)
	}
}

func TestApply_InventoryFindingsNeverSuppressed(t *testing.T) {
	b := New("1.0.0")
	b.Fingerprints = []string{"fp-inv"}
	b.fingerprintSet = map[string]struct{}{"fp-inv": {}}

	findings := []types.Finding{
		mkFinding("r-inv", "fp-inv", types.CategoryInventory),
	}
	res := Apply(findings, b)
	if len(res.Kept) != 1 {
		t.Fatalf("inventory finding must not be suppressed; kept %d", len(res.Kept))
	}
	if res.SuppressedCount != 0 {
		t.Errorf("SuppressedCount = %d, want 0", res.SuppressedCount)
	}
	// fp-inv never matched a suppressible finding → stale.
	if len(res.Stale) != 1 || res.Stale[0] != "fp-inv" {
		t.Errorf("Stale = %v, want [fp-inv]", res.Stale)
	}
}

func TestApply_EmptyCategoryTreatedAsSecurity(t *testing.T) {
	// Pre-lifecycle findings (tree-sitter Pass 1) have empty Category. They
	// must be baseline-eligible to mirror rulefilter's permissive default.
	b := New("1.0.0")
	b.Fingerprints = []string{"fp-pre"}
	b.fingerprintSet = map[string]struct{}{"fp-pre": {}}

	findings := []types.Finding{
		{RuleID: "pre", Fingerprint: "fp-pre"}, // Category left empty
	}
	res := Apply(findings, b)
	if len(res.Kept) != 0 || res.SuppressedCount != 1 {
		t.Errorf("empty-category should be suppressible: kept=%d suppressed=%d",
			len(res.Kept), res.SuppressedCount)
	}
}

func TestApply_ReportsStaleEntries(t *testing.T) {
	b := New("1.0.0")
	b.Fingerprints = []string{"fp-active", "fp-gone"}
	b.fingerprintSet = map[string]struct{}{
		"fp-active": {}, "fp-gone": {},
	}

	findings := []types.Finding{
		mkFinding("r", "fp-active", types.CategorySecurity),
	}
	res := Apply(findings, b)
	if res.SuppressedCount != 1 {
		t.Errorf("SuppressedCount = %d, want 1", res.SuppressedCount)
	}
	if len(res.Stale) != 1 || res.Stale[0] != "fp-gone" {
		t.Errorf("Stale = %v, want [fp-gone]", res.Stale)
	}
}

func TestApply_FindingWithoutFingerprintFlowsThrough(t *testing.T) {
	b := New("1.0.0")
	b.Fingerprints = []string{"fp-x"}
	b.fingerprintSet = map[string]struct{}{"fp-x": {}}

	findings := []types.Finding{
		mkFinding("r-nosig", "", types.CategorySecurity),
	}
	res := Apply(findings, b)
	if len(res.Kept) != 1 {
		t.Errorf("finding with empty fingerprint must survive; kept %d", len(res.Kept))
	}
}

func TestApply_PreservesOrder(t *testing.T) {
	b := New("1.0.0")
	b.fingerprintSet = map[string]struct{}{"fp-b": {}}
	b.Fingerprints = []string{"fp-b"}

	findings := []types.Finding{
		mkFinding("r-a", "fp-a", types.CategorySecurity),
		mkFinding("r-b", "fp-b", types.CategorySecurity), // will be suppressed
		mkFinding("r-c", "fp-c", types.CategorySecurity),
	}
	res := Apply(findings, b)
	if len(res.Kept) != 2 || res.Kept[0].RuleID != "r-a" || res.Kept[1].RuleID != "r-c" {
		t.Errorf("order not preserved: %+v", res.Kept)
	}
}

func TestBuildFromSecurityFindings_SkipsInventoryAndEmptyFingerprints(t *testing.T) {
	findings := []types.Finding{
		mkFinding("sec-1", "fp-sec-1", types.CategorySecurity),
		mkFinding("sec-2", "fp-sec-2", types.CategorySecurity),
		mkFinding("inv-1", "fp-inv-1", types.CategoryInventory), // skipped: inventory
		mkFinding("sec-3", "", types.CategorySecurity),          // skipped: no fp
		mkFinding("sec-1-dup", "fp-sec-1", types.CategorySecurity), // dedup
	}
	b, skipped := BuildFromSecurityFindings(findings, "1.0.0")
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (empty fingerprint)", skipped)
	}
	want := []string{"fp-sec-1", "fp-sec-2"}
	if !reflect.DeepEqual(b.Fingerprints, want) {
		t.Errorf("Fingerprints = %v, want %v", b.Fingerprints, want)
	}
	if b.CradarVersion != "1.0.0" {
		t.Errorf("CradarVersion = %q, want 1.0.0", b.CradarVersion)
	}
}

func TestBuildFromSecurityFindings_EmptyCategoryTreatedAsSecurity(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "r", Fingerprint: "fp-pre"},
	}
	b, skipped := BuildFromSecurityFindings(findings, "1.0.0")
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if len(b.Fingerprints) != 1 || b.Fingerprints[0] != "fp-pre" {
		t.Errorf("Fingerprints = %v, want [fp-pre]", b.Fingerprints)
	}
}
