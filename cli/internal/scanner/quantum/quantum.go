// Package quantum provides a shared quantum-readiness classification table
// for cryptographic algorithms. It is used by all language scanners and the
// output writers. Table data is embedded from quantum-readiness.yml.
package quantum

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

//go:embed quantum-readiness.yml
var quantumYAML []byte

// Info holds the quantum readiness classification for a crypto algorithm.
type Info struct {
	Status          types.QuantumStatus
	NistLevel       int    // 0 if not applicable
	Recommendation  string // migration guidance (free text)
	MigrationTarget string // structured replacement target, e.g. "ML-KEM / ML-DSA"
}

// yamlSchema mirrors the structure of quantum-readiness.yml.
type yamlSchema struct {
	Version                int                  `yaml:"version"`
	NonAlgorithmAssetTypes []string             `yaml:"non_algorithm_asset_types"`
	Algorithms             []yamlAlgorithmEntry `yaml:"algorithms"`
}

type yamlAlgorithmEntry struct {
	Family          string   `yaml:"family"`
	Status          string   `yaml:"status"`
	NistLevel       int      `yaml:"nist_level"`
	Recommendation  string   `yaml:"recommendation"`
	MigrationTarget string   `yaml:"migration_target"`
	Aliases         []string `yaml:"aliases"`
}

var (
	// table maps lowercase family names (and aliases) to Info.
	table map[string]Info
	// nonAlgorithmAssetTypes is the set of types.AssetType strings that should
	// skip the algorithm lookup entirely (cert, related-crypto-material, library).
	nonAlgorithmAssetTypes map[string]bool
)

// familySuffixRE strips key-size / mode suffixes for fuzzy family matching.
// Handles:
//   - "-2048", "-128-gcm"  → dash + digit-led token(s)
//   - "-P256"              → dash + alpha-prefix + digits (EC curve names)
//   - "123" (no dash)      → bare trailing digits (e.g. NotAlgorithm123)
//
// Preserves canonical names already in the table (sha-256, sha3-512).
var familySuffixRE = regexp.MustCompile(`(?i)(-[a-z]*\d+(-[a-z]+)?|\d+)$`)

func init() {
	var s yamlSchema
	if err := yaml.Unmarshal(quantumYAML, &s); err != nil {
		panic(fmt.Sprintf("quantum-readiness.yml is malformed: %v", err))
	}
	if s.Version != 1 {
		panic(fmt.Sprintf("quantum-readiness.yml unsupported version: %d", s.Version))
	}
	table = make(map[string]Info, len(s.Algorithms)*2)
	for _, a := range s.Algorithms {
		fam := strings.ToLower(a.Family)
		info := Info{
			Status:          types.QuantumStatus(a.Status),
			NistLevel:       a.NistLevel,
			Recommendation:  a.Recommendation,
			MigrationTarget: a.MigrationTarget,
		}
		table[fam] = info
		for _, alias := range a.Aliases {
			table[strings.ToLower(alias)] = info
		}
	}
	nonAlgorithmAssetTypes = make(map[string]bool, len(s.NonAlgorithmAssetTypes))
	for _, t := range s.NonAlgorithmAssetTypes {
		nonAlgorithmAssetTypes[strings.ToLower(t)] = true
	}
}

// GetInfo returns the quantum readiness info for a given algorithm family.
// The family name is normalized (suffix-stripped, lowercased, then alias-resolved).
// Returns QuantumUnknown if no match.
func GetInfo(algorithmFamily string) Info {
	if algorithmFamily == "" {
		return Info{Status: types.QuantumUnknown, Recommendation: "Algorithm not recognized — review manually"}
	}
	if info, ok := table[strings.ToLower(algorithmFamily)]; ok {
		return info
	}
	if family := normalizeFamily(algorithmFamily); family != "" {
		if info, ok := table[family]; ok {
			return info
		}
	}
	return Info{Status: types.QuantumUnknown, Recommendation: "Algorithm not recognized — review manually"}
}

// GetInfoForAsset is like GetInfo but skips the lookup for non-algorithm asset
// types (certificate, related-crypto-material, library) and returns
// QuantumNotApplicable, telling output writers to omit the quantum field.
func GetInfoForAsset(algorithmFamily, assetType string) Info {
	if assetType != "" && nonAlgorithmAssetTypes[strings.ToLower(assetType)] {
		return Info{Status: types.QuantumNotApplicable}
	}
	return GetInfo(algorithmFamily)
}

// normalizeFamily strips a -<digits>(-<mode>)? suffix and lowercases.
// Preserves the input if it matches the table exactly (so GetInfo can use
// names like "sha-256" or "sha3-512" where the suffix is part of the
// canonical name).
func normalizeFamily(s string) string {
	if s == "" {
		return ""
	}
	lower := strings.ToLower(strings.TrimSpace(s))
	if _, ok := table[lower]; ok {
		return lower
	}
	stripped := familySuffixRE.ReplaceAllString(lower, "")
	return stripped
}

// Priority returns the post-quantum migration urgency for an asset given its
// quantum status and CycloneDX primitive (e.g. "pke", "key-agree", "kem",
// "signature", "hash"). It follows the Harvest-Now-Decrypt-Later model:
//
//   - broken (classically): critical, regardless of primitive.
//   - quantum-vulnerable key-exchange/encryption (pke, key-agree, kem): critical
//     — captured ciphertext is retroactively decryptable once a CRQC exists.
//   - quantum-vulnerable signature: high — only needs to be safe by the deadline.
//   - quantum-vulnerable other primitive: medium.
//   - quantum-safe: none.
//   - unknown / not-applicable: empty (caller should omit).
func Priority(status types.QuantumStatus, primitive string) types.QuantumPriority {
	switch status {
	case types.Broken:
		return types.QuantumPriorityCritical
	case types.QuantumSafe:
		return types.QuantumPriorityNone
	case types.QuantumVulnerable:
		switch strings.ToLower(strings.TrimSpace(primitive)) {
		case "pke", "key-agree", "kem":
			return types.QuantumPriorityCritical
		case "signature":
			return types.QuantumPriorityHigh
		default:
			return types.QuantumPriorityMedium
		}
	default:
		return ""
	}
}
