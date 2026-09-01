package cmd

import (
	"sort"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
	"github.com/spf13/cobra"
)

// validAssetTypes is the closed set accepted by --asset-type / --exclude-type.
// "library" is a CycloneDX component type (ADR-040) carried on findings as
// AssetType "library"; the other four are the types.AssetType enum.
var validAssetTypes = map[string]bool{
	string(types.AssetAlgorithm):             true,
	string(types.AssetProtocol):              true,
	string(types.AssetCertificate):           true,
	string(types.AssetRelatedCryptoMaterial): true,
	"library":                                true,
}

func validAssetTypeList() string {
	ks := make([]string, 0, len(validAssetTypes))
	for k := range validAssetTypes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

// assetTypeSelection is the parsed, validated --asset-type / --exclude-type
// selection. include==nil means "keep all types"; exclude is applied after.
type assetTypeSelection struct {
	include map[string]bool
	exclude map[string]bool
}

// active reports whether any asset-type filtering was requested.
func (s assetTypeSelection) active() bool {
	return len(s.include) > 0 || len(s.exclude) > 0
}

// parseAssetTypeFlags reads and validates --asset-type / --exclude-type.
func parseAssetTypeFlags(cmd *cobra.Command) (assetTypeSelection, error) {
	inc, _ := cmd.Flags().GetStringSlice("asset-type")
	exc, _ := cmd.Flags().GetStringSlice("exclude-type")

	toSet := func(vals []string, flag string) (map[string]bool, error) {
		if len(vals) == 0 {
			return nil, nil
		}
		set := make(map[string]bool, len(vals))
		for _, v := range vals {
			key := strings.ToLower(strings.TrimSpace(v))
			if key == "" {
				continue // ignore stray empty entries (e.g. trailing comma)
			}
			if !validAssetTypes[key] {
				return nil, ExitErrorf(ExitConfig,
					"invalid --%s value %q (valid: %s)", flag, v, validAssetTypeList())
			}
			set[key] = true
		}
		if len(set) == 0 {
			return nil, nil
		}
		return set, nil
	}

	include, err := toSet(inc, "asset-type")
	if err != nil {
		return assetTypeSelection{}, err
	}
	exclude, err := toSet(exc, "exclude-type")
	if err != nil {
		return assetTypeSelection{}, err
	}
	return assetTypeSelection{include: include, exclude: exclude}, nil
}

// filterByAssetType keeps only findings whose AssetType is in include (when
// include is non-empty), then drops any whose AssetType is in exclude. An
// empty AssetType is treated as never matching an include and never excluded.
func filterByAssetType(findings []types.Finding, sel assetTypeSelection) []types.Finding {
	if !sel.active() {
		return findings
	}
	out := findings[:0:0] // new backing array, preserve nil-vs-empty semantics loosely
	for _, f := range findings {
		at := string(f.AssetType)
		if len(sel.include) > 0 && !sel.include[at] {
			continue
		}
		if sel.exclude[at] {
			continue
		}
		out = append(out, f)
	}
	return out
}
