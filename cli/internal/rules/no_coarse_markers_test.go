package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoCoarseMarkers asserts that no rule under scanner/rules/ uses a
// known placeholder token in cbom-primitive. Phase 3a (PR #4) introduced
// these markers intentionally as catch-alls; Phase C split them into
// per-algorithm rules. This test prevents new coarse-marker rules from
// sneaking in.
//
// Intentional exclusions (kept out of the coarse-marker list):
//
//   - CRYPTO-LIBRARY-IMPORT and CRYPTO-PROVIDER-REGISTRATION are real
//     category labels for library/registration assets, not placeholders.
//   - WEAK-PRNG is the canonical token for Math.random() / random.random()
//     / rand() — API-level signals with no underlying algorithm token to
//     substitute.
//   - SYMMETRIC-CIPHER and SYMMETRIC-KEY can still appear as
//     cbom-primitive-fallback values on rules that capture cipher-spec
//     strings via metavar; when the metavar fails to resolve we'd rather
//     emit a generic-but-typed asset than nothing. They are NOT used as
//     static cbom-primitive values (only as fallbacks), and the search
//     below only inspects `cbom-primitive:` (the static form).
func TestNoCoarseMarkers(t *testing.T) {
	coarse := []string{
		"PASSWORD-HASH",
		"DEPRECATED-CRYPTO",
		"CONFIG-DRIVEN-ALGORITHM",
	}

	rulesDir, err := findRulesDir()
	if err != nil {
		t.Skipf("rules dir not found: %v", err)
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}

	violations := map[string][]string{} // file -> []marker
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		path := filepath.Join(rulesDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		content := string(data)
		for _, marker := range coarse {
			// Check both static cbom-primitive and cbom-primitive-fallback;
			// either form fabricates a coarse algorithm token.
			for _, needle := range []string{
				"cbom-primitive: " + marker,
				"cbom-primitive-fallback: " + marker,
			} {
				if strings.Contains(content, needle) {
					violations[e.Name()] = append(violations[e.Name()], marker)
				}
			}
		}
	}

	if len(violations) > 0 {
		for file, markers := range violations {
			t.Errorf("rule file %s still uses coarse marker(s): %v — split into per-algorithm rules", file, markers)
		}
	}
}

// findRulesDir locates scanner/rules/ from the test's working directory.
// Tests run from the package dir (cli/internal/rules); walk up to the
// repo root and look for scanner/rules.
func findRulesDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(wd, "scanner", "rules")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", os.ErrNotExist
		}
		wd = parent
	}
}
