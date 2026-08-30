package cmd

import (
	"errors"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/spf13/cobra"
)

func mkFindings() []types.Finding {
	return []types.Finding{
		{RuleID: "a", AssetType: types.AssetAlgorithm},
		{RuleID: "p", AssetType: types.AssetProtocol},
		{RuleID: "c", AssetType: types.AssetCertificate},
		{RuleID: "m", AssetType: types.AssetRelatedCryptoMaterial},
		{RuleID: "l", AssetType: types.AssetType("library")},
	}
}

func typesOf(fs []types.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[string(f.AssetType)] = true
	}
	return m
}

func TestFilterByAssetType_Include(t *testing.T) {
	sel := assetTypeSelection{include: map[string]bool{"algorithm": true, "certificate": true}}
	got := typesOf(filterByAssetType(mkFindings(), sel))
	if !got["algorithm"] || !got["certificate"] {
		t.Errorf("include should keep algorithm+certificate, got %v", got)
	}
	if got["protocol"] || got["library"] || got["related-crypto-material"] {
		t.Errorf("include should drop others, got %v", got)
	}
}

func TestFilterByAssetType_Exclude(t *testing.T) {
	sel := assetTypeSelection{exclude: map[string]bool{"related-crypto-material": true, "library": true}}
	got := typesOf(filterByAssetType(mkFindings(), sel))
	if got["related-crypto-material"] || got["library"] {
		t.Errorf("exclude should drop those types, got %v", got)
	}
	if !got["algorithm"] || !got["protocol"] || !got["certificate"] {
		t.Errorf("exclude should keep the rest, got %v", got)
	}
}

func TestFilterByAssetType_IncludeThenExclude(t *testing.T) {
	// include algorithm+certificate, then exclude certificate → only algorithm.
	sel := assetTypeSelection{
		include: map[string]bool{"algorithm": true, "certificate": true},
		exclude: map[string]bool{"certificate": true},
	}
	got := typesOf(filterByAssetType(mkFindings(), sel))
	if !got["algorithm"] || got["certificate"] || len(got) != 1 {
		t.Errorf("expected only algorithm, got %v", got)
	}
}

func TestFilterByAssetType_Inactive(t *testing.T) {
	in := mkFindings()
	out := filterByAssetType(in, assetTypeSelection{})
	if len(out) != len(in) {
		t.Errorf("no filter should be a no-op: got %d want %d", len(out), len(in))
	}
}

func TestParseAssetTypeFlags_Validation(t *testing.T) {
	// Use a throwaway command so we don't mutate the process-global scanCmd
	// (pflag StringSlice appends once Changed=true, which would leak into
	// other command tests).
	newCmd := func(at, et []string) *cobra.Command {
		c := &cobra.Command{}
		c.Flags().StringSlice("asset-type", at, "")
		c.Flags().StringSlice("exclude-type", et, "")
		return c
	}

	// Valid (case-insensitive, trimmed).
	if _, err := parseAssetTypeFlags(newCmd([]string{"Algorithm", " certificate "}, nil)); err != nil {
		t.Errorf("valid asset-type rejected: %v", err)
	}
	// Invalid value → ExitConfig.
	_, err := parseAssetTypeFlags(newCmd(nil, []string{"bogus"}))
	if err == nil {
		t.Fatal("expected error for invalid --exclude-type, got nil")
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitConfig {
		t.Errorf("expected ExitConfig, got %v", err)
	}
}
