package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// LoadCBOM loads a CycloneDX 1.7 JSON file and extracts findings.
func LoadCBOM(path string) ([]types.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CBOM file %s: %w", path, err)
	}

	var bom output.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing CBOM file %s: %w", path, err)
	}

	findings := make([]types.Finding, 0, len(bom.Components))
	for i, comp := range bom.Components {
		f := componentToFinding(comp, i)
		findings = append(findings, f)
	}

	return findings, nil
}

// componentToFinding converts a CycloneDX component back to a Finding.
func componentToFinding(comp output.Component, index int) types.Finding {
	f := types.Finding{
		ID:          comp.BOMRef,
		Name:        comp.Name,
		Description: comp.Description,
	}

	// If ID is empty, generate one.
	if f.ID == "" {
		f.ID = fmt.Sprintf("CBOM-%d", index+1)
	}

	// Extract location from evidence.
	if comp.Evidence != nil && len(comp.Evidence.Occurrences) > 0 {
		occ := comp.Evidence.Occurrences[0]
		f.Location = types.Location{
			File:      occ.Location,
			StartLine: occ.Line,
		}
	}

	// Extract crypto properties from CycloneDX cryptoProperties.
	if comp.CryptoProperties != nil {
		cp := comp.CryptoProperties
		f.AssetType = types.AssetType(cp.AssetType)

		switch f.AssetType {
		case types.AssetAlgorithm:
			if cp.AlgorithmProperties != nil {
				ap := cp.AlgorithmProperties
				f.Properties.Primitive = string(ap.Primitive)
				f.Properties.AlgorithmFamily = string(ap.AlgorithmFamily)
				f.Properties.Mode = string(ap.Mode)
				f.Properties.Padding = string(ap.Padding)
				f.Properties.ClassicalSecurity = ap.ClassicalSecurityLevel
				f.Properties.NistQuantumLevel = ap.NistQuantumSecurityLevel
				// KeySize: use ClassicalSecurityLevel as a proxy if no explicit key size.
				if ap.ClassicalSecurityLevel > 0 {
					f.Properties.KeySize = ap.ClassicalSecurityLevel
				}
				if len(ap.CryptoFunctions) > 0 {
					funcs := make([]string, 0, len(ap.CryptoFunctions))
					for _, fn := range ap.CryptoFunctions {
						funcs = append(funcs, string(fn))
					}
					f.Properties.CryptoFunctions = funcs
				}
			}
		case types.AssetProtocol:
			if cp.ProtocolProperties != nil {
				pp := cp.ProtocolProperties
				f.Properties.ProtocolType = pp.Type
				f.Properties.ProtocolVersion = pp.Version
				if len(pp.CipherSuites) > 0 {
					suites := make([]string, 0, len(pp.CipherSuites))
					for _, cs := range pp.CipherSuites {
						suites = append(suites, cs.Name)
					}
					f.Properties.CipherSuites = suites
				}
			}
		case types.AssetCertificate:
			if cp.CertificateProperties != nil {
				certP := cp.CertificateProperties
				f.Properties.SubjectName = certP.SubjectName
				f.Properties.IssuerName = certP.IssuerName
				f.Properties.NotValidBefore = certP.NotValidBefore
				f.Properties.NotValidAfter = certP.NotValidAfter
				f.Properties.CertificateFormat = certP.CertificateFormat
			}
		case types.AssetRelatedCryptoMaterial:
			if cp.RelatedCryptoMaterialProperties != nil {
				rp := cp.RelatedCryptoMaterialProperties
				f.Properties.MaterialType = string(rp.Type)
				f.Properties.State = string(rp.State)
				f.Properties.MaterialSize = rp.Size
			}
		}

		// Infer quantum status from algorithm family if not explicitly set.
		if f.Properties.QuantumStatus == "" {
			f.Properties.QuantumStatus = inferQuantumStatus(f.Properties.AlgorithmFamily)
		}

		// Infer severity if not set.
		if f.Severity == "" {
			f.Severity = inferSeverity(&f)
		}
	}

	return f
}

// inferQuantumStatus infers the quantum status from the algorithm family.
func inferQuantumStatus(algoFamily string) types.QuantumStatus {
	lower := strings.ToLower(algoFamily)
	switch lower {
	case "md5", "sha1", "des", "3des", "rc4":
		return types.Broken
	case "rsa", "ecdsa", "ecdh", "dsa", "dh", "ec", "ed25519", "ed448", "x25519", "x448":
		return types.QuantumVulnerable
	case "ml-kem", "ml-dsa", "slh-dsa", "falcon", "bike", "hqc", "classic-mceliece",
		"frodokem", "ntru", "saber", "kyber", "dilithium", "sphincs":
		return types.QuantumSafe
	case "aes", "sha2", "sha3", "chacha20", "blake2", "blake3":
		// Symmetric and modern hashes are generally quantum-safe at sufficient key sizes.
		return types.QuantumSafe
	default:
		return types.QuantumUnknown
	}
}

// inferSeverity infers the severity from the finding's properties.
func inferSeverity(f *types.Finding) types.Severity {
	switch f.Properties.QuantumStatus {
	case types.Broken:
		return types.SeverityCritical
	case types.QuantumVulnerable:
		return types.SeverityMedium
	default:
		return types.SeverityInfo
	}
}
