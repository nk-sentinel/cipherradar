// Package baseline implements fingerprint-based suppression for previously
// acknowledged findings. It backs the --update-baseline / --no-baseline flags
// and the .cradar-baseline.json file format.
//
// Scope
//
// Baseline suppression applies ONLY to findings where Category == security.
// Inventory findings are statements of fact (this algorithm is used here) and
// are not "acknowledged" — they always flow through unchanged. Findings with
// empty/unknown category fall back to the rulefilter permissive default
// (security) and are eligible for suppression.
//
// File format (schema version 1)
//
//	{
//	  "version": 1,
//	  "created": "2026-04-14T12:34:56Z",
//	  "cradar_version": "1.2.3",
//	  "fingerprints": [
//	    "a1b2c3…",
//	    "d4e5f6…"
//	  ]
//	}
//
// Fingerprints are the stable identity hash from
// cli/internal/scanner/fingerprint: SHA256(rule_id + ":" + file + ":" + signature).
// Same rule + same file + same normalized code → same fingerprint, so baseline
// entries survive whitespace-only refactors and reruns.
//
// Stale entries
//
// When a finding disappears (code deleted, rule removed) its fingerprint
// remains in the baseline — "stale". Apply reports these so the user can
// clean them up with `cradar scan --update-baseline`.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// DefaultFile is the conventional filename checked into the repo root.
const DefaultFile = ".cradar-baseline.json"

// SchemaVersion is the current file-format version. Bumped when backward-
// incompatible changes land; Load accepts any schema <= SchemaVersion.
const SchemaVersion = 1

// Baseline represents one .cradar-baseline.json file. Fingerprints is stored
// as a set for O(1) membership tests.
type Baseline struct {
	Version        int                 `json:"version"`
	Created        time.Time           `json:"created"`
	CradarVersion  string              `json:"cradar_version"`
	Fingerprints   []string            `json:"fingerprints"`
	fingerprintSet map[string]struct{} `json:"-"`
}

// New constructs an empty Baseline ready for Save.
func New(cradarVersion string) *Baseline {
	return &Baseline{
		Version:        SchemaVersion,
		Created:        time.Now().UTC(),
		CradarVersion:  cradarVersion,
		Fingerprints:   []string{},
		fingerprintSet: map[string]struct{}{},
	}
}

// Load reads a baseline file. Returns (nil, nil) if the file does not exist
// — baseline is always optional. A malformed file returns an error so the
// user can see the problem instead of silently losing acknowledgments.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}

	if b.Version > SchemaVersion {
		return nil, fmt.Errorf(
			"baseline %s has version %d; this cradar supports up to %d (upgrade cradar)",
			path, b.Version, SchemaVersion)
	}

	b.fingerprintSet = make(map[string]struct{}, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		if fp != "" {
			b.fingerprintSet[fp] = struct{}{}
		}
	}
	return &b, nil
}

// Save writes the baseline to path atomically (write to tmp + rename). The
// fingerprint slice is sorted for deterministic diffs.
func Save(path string, b *Baseline) error {
	out := *b
	out.Fingerprints = append([]string(nil), b.Fingerprints...)
	sort.Strings(out.Fingerprints)

	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write baseline tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename baseline: %w", err)
	}
	return nil
}

// Contains returns true if the given fingerprint is in the baseline.
func (b *Baseline) Contains(fingerprint string) bool {
	if b == nil || fingerprint == "" {
		return false
	}
	_, ok := b.fingerprintSet[fingerprint]
	return ok
}

// Result reports what Apply did.
type Result struct {
	// Kept is the list of findings that were NOT suppressed by the baseline
	// (input order preserved).
	Kept []types.Finding
	// SuppressedCount is how many findings matched the baseline.
	SuppressedCount int
	// Stale is the list of baseline fingerprints that no finding matched
	// during this scan — typically means the code was fixed or the rule
	// was renamed/removed. Safe to clean up with --update-baseline.
	Stale []string
}

// Apply suppresses findings whose fingerprint is in the baseline. Only
// findings with Category == security (or the rulefilter "unknown ->
// security" default, i.e. empty Category) are eligible for suppression —
// inventory findings are never suppressed.
//
// If b is nil (no baseline file), Apply is a no-op: all findings kept,
// zero suppressed, no stale entries.
func Apply(findings []types.Finding, b *Baseline) Result {
	if b == nil {
		return Result{Kept: findings}
	}

	matched := make(map[string]struct{}, len(b.Fingerprints))
	kept := make([]types.Finding, 0, len(findings))
	suppressed := 0

	for _, f := range findings {
		if !isSuppressible(f) {
			kept = append(kept, f)
			continue
		}
		if f.Fingerprint != "" && b.Contains(f.Fingerprint) {
			matched[f.Fingerprint] = struct{}{}
			suppressed++
			continue
		}
		kept = append(kept, f)
	}

	// Baseline entries we never matched this run → stale.
	stale := make([]string, 0)
	for _, fp := range b.Fingerprints {
		if _, ok := matched[fp]; !ok {
			stale = append(stale, fp)
		}
	}
	sort.Strings(stale)

	return Result{
		Kept:            kept,
		SuppressedCount: suppressed,
		Stale:           stale,
	}
}

// BuildFromSecurityFindings creates a new Baseline containing the
// fingerprints of every eligible (security-category) finding. Called by
// --update-baseline. Findings without a computed Fingerprint are skipped
// with a warning (caller's responsibility to log).
func BuildFromSecurityFindings(findings []types.Finding, cradarVersion string) (*Baseline, int) {
	b := New(cradarVersion)
	skipped := 0
	for _, f := range findings {
		if !isSuppressible(f) {
			continue
		}
		if f.Fingerprint == "" {
			skipped++
			continue
		}
		if _, exists := b.fingerprintSet[f.Fingerprint]; exists {
			continue
		}
		b.fingerprintSet[f.Fingerprint] = struct{}{}
		b.Fingerprints = append(b.Fingerprints, f.Fingerprint)
	}
	sort.Strings(b.Fingerprints)
	return b, skipped
}

// isSuppressible returns true for findings eligible for baseline suppression.
// Inventory findings are statements of fact and are never suppressed. Empty
// Category falls through to "security" to mirror rulefilter's permissive
// default, so Pass 1 (tree-sitter) findings without category annotation
// remain eligible.
func isSuppressible(f types.Finding) bool {
	return f.Category != types.CategoryInventory
}
