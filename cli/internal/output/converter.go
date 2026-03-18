package output

import (
	"crypto/rand"
	"fmt"
	"sort"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// BOM represents a complete CycloneDX 1.7 CBOM document.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	Version      int         `json:"version"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Metadata     *Metadata   `json:"metadata,omitempty"`
	Components   []Component `json:"components,omitempty"`
}

// Metadata for the BOM.
type Metadata struct {
	Timestamp string `json:"timestamp,omitempty"`
	Tools     []Tool `json:"tools,omitempty"`
}

// Tool represents a tool that generated or contributed to the BOM.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor,omitempty"`
}

// Component represents a CycloneDX component with cryptoProperties.
type Component struct {
	Type             string                       `json:"type"`
	BOMRef           string                       `json:"bom-ref,omitempty"`
	Name             string                       `json:"name"`
	Description      string                       `json:"description,omitempty"`
	CryptoProperties *cyclonedx17.CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence                    `json:"evidence,omitempty"`
}

// Evidence captures where a component was detected.
type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence pinpoints a location in the source where the component was found.
type Occurrence struct {
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// cipherRadarVersion is the version string embedded in BOM metadata.
const cipherRadarVersion = "0.1.0"

// generateUUID4 produces a random UUID v4 string.
func generateUUID4() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// ConvertScanResult converts a types.ScanResult to a CycloneDX 1.7 BOM.
func ConvertScanResult(result *types.ScanResult) *BOM {
	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		Version:      1,
		SerialNumber: generateUUID4(),
		Metadata: &Metadata{
			Timestamp: result.StartTime.UTC().Format("2006-01-02T15:04:05Z"),
			Tools: []Tool{
				{
					Name:    "CipherRadar",
					Version: cipherRadarVersion,
					Vendor:  "nk-sentinel",
				},
			},
		},
	}

	components := make([]Component, 0, len(result.Findings))
	for i := range result.Findings {
		components = append(components, convertFinding(&result.Findings[i]))
	}

	// Sort components by bom-ref for deterministic output.
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})

	bom.Components = components
	return bom
}

// convertFinding maps a single types.Finding to a CycloneDX Component.
func convertFinding(f *types.Finding) Component {
	comp := Component{
		Type:        "cryptographic-asset",
		BOMRef:      f.ID,
		Name:        f.Name,
		Description: f.Description,
		Evidence: &Evidence{
			Occurrences: []Occurrence{
				{
					Location: f.Location.File,
					Line:     f.Location.StartLine,
				},
			},
		},
	}

	cp := convertCryptoProperties(f)
	comp.CryptoProperties = cp
	return comp
}

// convertCryptoProperties builds CycloneDX 1.7 cryptoProperties from a Finding.
func convertCryptoProperties(f *types.Finding) *cyclonedx17.CryptoProperties {
	cp := &cyclonedx17.CryptoProperties{
		AssetType: string(f.AssetType),
	}

	props := &f.Properties

	switch f.AssetType {
	case types.AssetAlgorithm:
		cp.AlgorithmProperties = convertAlgorithmProperties(props)
	case types.AssetProtocol:
		cp.ProtocolProperties = convertProtocolProperties(props)
	case types.AssetCertificate:
		cp.CertificateProperties = convertCertificateProperties(props)
	case types.AssetRelatedCryptoMaterial:
		cp.RelatedCryptoMaterialProperties = convertRelatedCryptoMaterialProperties(props)
	}

	return cp
}

// convertAlgorithmProperties maps types.CryptoProperties to CycloneDX AlgorithmProperties.
func convertAlgorithmProperties(p *types.CryptoProperties) *cyclonedx17.AlgorithmProperties {
	ap := &cyclonedx17.AlgorithmProperties{
		Primitive:                cyclonedx17.Primitive(p.Primitive),
		AlgorithmFamily:          cyclonedx17.AlgorithmFamily(p.AlgorithmFamily),
		Mode:                     cyclonedx17.Mode(p.Mode),
		Padding:                  cyclonedx17.Padding(p.Padding),
		ClassicalSecurityLevel:   p.ClassicalSecurity,
		NistQuantumSecurityLevel: p.NistQuantumLevel,
	}

	// For symmetric ciphers, use KeySize as classical security level if ClassicalSecurity is unset.
	if ap.ClassicalSecurityLevel == 0 && p.KeySize > 0 {
		ap.ClassicalSecurityLevel = p.KeySize
	}

	if len(p.CryptoFunctions) > 0 {
		funcs := make([]cyclonedx17.CryptoFunction, 0, len(p.CryptoFunctions))
		for _, fn := range p.CryptoFunctions {
			funcs = append(funcs, cyclonedx17.CryptoFunction(fn))
		}
		ap.CryptoFunctions = funcs
	}

	return ap
}

// convertProtocolProperties maps types.CryptoProperties to CycloneDX ProtocolProperties.
func convertProtocolProperties(p *types.CryptoProperties) *cyclonedx17.ProtocolProperties {
	pp := &cyclonedx17.ProtocolProperties{
		Type:    p.ProtocolType,
		Version: p.ProtocolVersion,
	}

	if len(p.CipherSuites) > 0 {
		suites := make([]cyclonedx17.CipherSuite, 0, len(p.CipherSuites))
		for _, name := range p.CipherSuites {
			suites = append(suites, cyclonedx17.CipherSuite{Name: name})
		}
		pp.CipherSuites = suites
	}

	return pp
}

// convertCertificateProperties maps types.CryptoProperties to CycloneDX CertificateProperties.
func convertCertificateProperties(p *types.CryptoProperties) *cyclonedx17.CertificateProperties {
	return &cyclonedx17.CertificateProperties{
		SubjectName:       p.SubjectName,
		IssuerName:        p.IssuerName,
		NotValidBefore:    p.NotValidBefore,
		NotValidAfter:     p.NotValidAfter,
		CertificateFormat: p.CertificateFormat,
	}
}

// convertRelatedCryptoMaterialProperties maps types.CryptoProperties to CycloneDX RelatedCryptoMaterialProperties.
func convertRelatedCryptoMaterialProperties(p *types.CryptoProperties) *cyclonedx17.RelatedCryptoMaterialProperties {
	return &cyclonedx17.RelatedCryptoMaterialProperties{
		Type:  cyclonedx17.RelatedCryptoMaterialType(p.MaterialType),
		State: cyclonedx17.RelatedCryptoMaterialState(p.State),
		Size:  p.MaterialSize,
	}
}
