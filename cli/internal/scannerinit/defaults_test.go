package scannerinit

import (
	"testing"

	cradarConfig "github.com/nk-sentinel/cipherradar/cli/internal/config"
)

func TestDefaultRegistry_HasBuiltinLanguageScanners(t *testing.T) {
	r := DefaultRegistry()
	// Spot-check a handful of extensions we always expect to dispatch.
	for _, ext := range []string{".py", ".java", ".go", ".ts"} {
		if s := r.ForExtension(ext); s == nil {
			t.Errorf("DefaultRegistry missing scanner for %q", ext)
		}
	}
	if len(r.Universals()) == 0 {
		t.Error("DefaultRegistry must register at least one universal scanner (regex)")
	}
}

func TestDefaultRegistryWithConfig_NilConfigSameAsDefault(t *testing.T) {
	baseUniv := len(DefaultRegistry().Universals())
	got := DefaultRegistryWithConfig(nil)
	if len(got.Universals()) != baseUniv {
		t.Errorf("nil config must not add universals; got %d want %d",
			len(got.Universals()), baseUniv)
	}
}

func TestDefaultRegistryWithConfig_EmptyWrappersSameAsDefault(t *testing.T) {
	baseUniv := len(DefaultRegistry().Universals())
	got := DefaultRegistryWithConfig(&cradarConfig.Config{})
	if len(got.Universals()) != baseUniv {
		t.Errorf("empty CustomWrappers must not add a universal; got %d want %d",
			len(got.Universals()), baseUniv)
	}
}

func TestDefaultRegistryWithConfig_AddsCustomScannerWhenWrappersDeclared(t *testing.T) {
	baseUniv := len(DefaultRegistry().Universals())
	cfg := &cradarConfig.Config{
		CustomWrappers: []cradarConfig.CustomWrapper{
			{
				Name:       "mycorp.crypto.encrypt",
				Language:   "python",
				Type:       "algorithm",
				Severity:   "medium",
				Parameters: map[string]int{"key": 0},
			},
		},
	}
	got := DefaultRegistryWithConfig(cfg)
	if len(got.Universals()) != baseUniv+1 {
		t.Fatalf("wrappers configured but CustomScanner not registered; got %d want %d",
			len(got.Universals()), baseUniv+1)
	}
	// The custom scanner registers itself under name "custom".
	var found bool
	for _, u := range got.Universals() {
		if u.Name() == "custom" {
			found = true
			break
		}
	}
	if !found {
		t.Error(`universal with Name()=="custom" missing from registry`)
	}
}
