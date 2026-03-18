package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
	"github.com/nk-sentinel/cipherradar/cli/internal/output"
)

// DiffResult holds the comparison between two CBOMs.
type DiffResult struct {
	Before    string             // path/name of the before CBOM
	After     string             // path/name of the after CBOM
	Added     []output.Component // components in After but not Before
	Removed   []output.Component // components in Before but not After
	Changed   []ChangedComponent // components present in both but with differences
	Unchanged int                // count of identical components
}

// ChangedComponent describes a component that exists in both CBOMs but differs.
type ChangedComponent struct {
	BOMRef  string
	Name    string
	Before  output.Component
	After   output.Component
	Changes []string // human-readable list of what changed
}

// componentKey returns the key used to match a component across two BOMs.
// It uses bom-ref if available, otherwise falls back to name + first occurrence location.
func componentKey(c *output.Component) string {
	if c.BOMRef != "" {
		return c.BOMRef
	}
	loc := ""
	if c.Evidence != nil && len(c.Evidence.Occurrences) > 0 {
		occ := c.Evidence.Occurrences[0]
		loc = fmt.Sprintf("%s:%d", occ.Location, occ.Line)
	}
	return c.Name + "|" + loc
}

// CompareBOMs compares two CycloneDX BOM documents and returns the differences.
func CompareBOMs(before, after *output.BOM) *DiffResult {
	result := &DiffResult{}

	// Build maps keyed by componentKey.
	beforeMap := make(map[string]*output.Component)
	afterMap := make(map[string]*output.Component)

	if before != nil {
		for i := range before.Components {
			key := componentKey(&before.Components[i])
			beforeMap[key] = &before.Components[i]
		}
	}
	if after != nil {
		for i := range after.Components {
			key := componentKey(&after.Components[i])
			afterMap[key] = &after.Components[i]
		}
	}

	// Collect all keys in sorted order for deterministic output.
	allKeys := make(map[string]struct{})
	for k := range beforeMap {
		allKeys[k] = struct{}{}
	}
	for k := range afterMap {
		allKeys[k] = struct{}{}
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		bc, inBefore := beforeMap[key]
		ac, inAfter := afterMap[key]

		switch {
		case inBefore && !inAfter:
			result.Removed = append(result.Removed, *bc)
		case !inBefore && inAfter:
			result.Added = append(result.Added, *ac)
		case inBefore && inAfter:
			changes := compareComponents(bc, ac)
			if len(changes) == 0 {
				result.Unchanged++
			} else {
				result.Changed = append(result.Changed, ChangedComponent{
					BOMRef:  ac.BOMRef,
					Name:    bc.Name,
					Before:  *bc,
					After:   *ac,
					Changes: changes,
				})
			}
		}
	}

	return result
}

// compareComponents returns a list of human-readable changes between two components.
// An empty list means the components are identical.
func compareComponents(before, after *output.Component) []string {
	var changes []string

	if before.Name != after.Name {
		changes = append(changes, fmt.Sprintf("Name: %s \u2192 %s", before.Name, after.Name))
	}
	if before.Description != after.Description {
		changes = append(changes, fmt.Sprintf("Description: %q \u2192 %q", before.Description, after.Description))
	}

	changes = append(changes, compareCryptoProperties(before, after)...)

	return changes
}

// compareCryptoProperties compares cryptoProperties between two components.
func compareCryptoProperties(before, after *output.Component) []string {
	var changes []string

	bcp := before.CryptoProperties
	acp := after.CryptoProperties

	// Handle nil cases.
	if bcp == nil && acp == nil {
		return nil
	}
	if bcp == nil {
		changes = append(changes, "Crypto properties: added")
		return changes
	}
	if acp == nil {
		changes = append(changes, "Crypto properties: removed")
		return changes
	}

	if bcp.AssetType != acp.AssetType {
		changes = append(changes, fmt.Sprintf("Asset type: %s \u2192 %s", bcp.AssetType, acp.AssetType))
	}

	// Compare algorithm properties.
	changes = append(changes, compareAlgorithmProperties(bcp.AlgorithmProperties, acp.AlgorithmProperties)...)

	// Compare protocol properties.
	changes = append(changes, compareProtocolProperties(bcp.ProtocolProperties, acp.ProtocolProperties)...)

	// Compare certificate properties.
	changes = append(changes, compareCertificateProperties(bcp.CertificateProperties, acp.CertificateProperties)...)

	// Compare related crypto material properties.
	changes = append(changes, compareRelatedCryptoMaterialProperties(
		bcp.RelatedCryptoMaterialProperties, acp.RelatedCryptoMaterialProperties)...)

	return changes
}

// compareAlgorithmProperties compares algorithm properties between two components.
func compareAlgorithmProperties(before, after *cyclonedx17.AlgorithmProperties) []string {
	if before == nil && after == nil {
		return nil
	}
	var changes []string
	if before == nil {
		changes = append(changes, "Algorithm properties: added")
		return changes
	}
	if after == nil {
		changes = append(changes, "Algorithm properties: removed")
		return changes
	}

	if string(before.Primitive) != string(after.Primitive) {
		changes = append(changes, fmt.Sprintf("Primitive: %s \u2192 %s", before.Primitive, after.Primitive))
	}
	if string(before.AlgorithmFamily) != string(after.AlgorithmFamily) {
		changes = append(changes, fmt.Sprintf("Algorithm family: %s \u2192 %s", before.AlgorithmFamily, after.AlgorithmFamily))
	}
	if string(before.Mode) != string(after.Mode) {
		changes = append(changes, fmt.Sprintf("Mode: %s \u2192 %s", before.Mode, after.Mode))
	}
	if string(before.Padding) != string(after.Padding) {
		changes = append(changes, fmt.Sprintf("Padding: %s \u2192 %s", before.Padding, after.Padding))
	}
	if before.ClassicalSecurityLevel != after.ClassicalSecurityLevel {
		changes = append(changes, fmt.Sprintf("Key size: %d \u2192 %d", before.ClassicalSecurityLevel, after.ClassicalSecurityLevel))
	}
	if before.NistQuantumSecurityLevel != after.NistQuantumSecurityLevel {
		changes = append(changes, fmt.Sprintf("NIST quantum security level: %d \u2192 %d", before.NistQuantumSecurityLevel, after.NistQuantumSecurityLevel))
	}

	bFuncs := cryptoFunctionsString(before.CryptoFunctions)
	aFuncs := cryptoFunctionsString(after.CryptoFunctions)
	if bFuncs != aFuncs {
		changes = append(changes, fmt.Sprintf("Crypto functions: [%s] \u2192 [%s]", bFuncs, aFuncs))
	}

	return changes
}

// compareProtocolProperties compares protocol properties between two components.
func compareProtocolProperties(before, after *cyclonedx17.ProtocolProperties) []string {
	if before == nil && after == nil {
		return nil
	}
	var changes []string
	if before == nil {
		changes = append(changes, "Protocol properties: added")
		return changes
	}
	if after == nil {
		changes = append(changes, "Protocol properties: removed")
		return changes
	}

	if before.Type != after.Type {
		changes = append(changes, fmt.Sprintf("Protocol type: %s \u2192 %s", before.Type, after.Type))
	}
	if before.Version != after.Version {
		changes = append(changes, fmt.Sprintf("Protocol version: %s \u2192 %s", before.Version, after.Version))
	}

	bSuites := cipherSuitesString(before.CipherSuites)
	aSuites := cipherSuitesString(after.CipherSuites)
	if bSuites != aSuites {
		changes = append(changes, fmt.Sprintf("Cipher suites: [%s] \u2192 [%s]", bSuites, aSuites))
	}

	return changes
}

// compareCertificateProperties compares certificate properties between two components.
func compareCertificateProperties(before, after *cyclonedx17.CertificateProperties) []string {
	if before == nil && after == nil {
		return nil
	}
	var changes []string
	if before == nil {
		changes = append(changes, "Certificate properties: added")
		return changes
	}
	if after == nil {
		changes = append(changes, "Certificate properties: removed")
		return changes
	}

	if before.SubjectName != after.SubjectName {
		changes = append(changes, fmt.Sprintf("Subject name: %s \u2192 %s", before.SubjectName, after.SubjectName))
	}
	if before.IssuerName != after.IssuerName {
		changes = append(changes, fmt.Sprintf("Issuer name: %s \u2192 %s", before.IssuerName, after.IssuerName))
	}
	if before.CertificateFormat != after.CertificateFormat {
		changes = append(changes, fmt.Sprintf("Certificate format: %s \u2192 %s", before.CertificateFormat, after.CertificateFormat))
	}

	return changes
}

// compareRelatedCryptoMaterialProperties compares related crypto material properties.
func compareRelatedCryptoMaterialProperties(before, after *cyclonedx17.RelatedCryptoMaterialProperties) []string {
	if before == nil && after == nil {
		return nil
	}
	var changes []string
	if before == nil {
		changes = append(changes, "Related crypto material properties: added")
		return changes
	}
	if after == nil {
		changes = append(changes, "Related crypto material properties: removed")
		return changes
	}

	if string(before.Type) != string(after.Type) {
		changes = append(changes, fmt.Sprintf("Material type: %s \u2192 %s", before.Type, after.Type))
	}
	if string(before.State) != string(after.State) {
		changes = append(changes, fmt.Sprintf("Material state: %s \u2192 %s", before.State, after.State))
	}
	if before.Size != after.Size {
		changes = append(changes, fmt.Sprintf("Material size: %d \u2192 %d", before.Size, after.Size))
	}

	return changes
}

// cryptoFunctionsString returns a sorted, comma-separated string of crypto functions.
func cryptoFunctionsString(funcs []cyclonedx17.CryptoFunction) string {
	if len(funcs) == 0 {
		return ""
	}
	strs := make([]string, len(funcs))
	for i, f := range funcs {
		strs[i] = string(f)
	}
	sort.Strings(strs)
	return strings.Join(strs, ", ")
}

// cipherSuitesString returns a sorted, comma-separated string of cipher suite names.
func cipherSuitesString(suites []cyclonedx17.CipherSuite) string {
	if len(suites) == 0 {
		return ""
	}
	names := make([]string, len(suites))
	for i, s := range suites {
		names[i] = s.Name
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
