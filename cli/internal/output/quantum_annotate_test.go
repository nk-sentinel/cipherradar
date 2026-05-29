package output

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// TestAnnotateQuantum_Pass2 covers issue #30: Pass-2 (OpenGrep) findings reach
// the converter with only AlgorithmPrimitive set and no quantum posture. The
// annotator must derive QuantumStatus + NistQuantumLevel from quantum.GetInfo
// for findings with a resolvable algorithm family, while leaving genuinely
// unresolvable / non-algorithm findings blank.
func TestAnnotateQuantum_Pass2(t *testing.T) {
	tests := []struct {
		name     string
		finding  types.Finding
		wantQS   types.QuantumStatus // "" means must stay blank
		wantNist int
	}{
		{
			name: "elgamal token → quantum-vulnerable",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "ELGAMAL"},
			},
			wantQS:   types.QuantumVulnerable,
			wantNist: 0,
		},
		{
			name: "explicit algorithmFamily=elgamal → quantum-vulnerable",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmFamily: "elgamal"},
			},
			wantQS:   types.QuantumVulnerable,
			wantNist: 0,
		},
		{
			name: "P-256 EC curve token → quantum-vulnerable",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "P-256"},
			},
			wantQS:   types.QuantumVulnerable,
			wantNist: 0,
		},
		{
			name: "CURVE25519 token → quantum-vulnerable",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "CURVE25519"},
			},
			wantQS:   types.QuantumVulnerable,
			wantNist: 0,
		},
		{
			name: "ED448 token → quantum-vulnerable",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "ED448"},
			},
			wantQS:   types.QuantumVulnerable,
			wantNist: 0,
		},
		{
			name: "AES-256-GCM token → quantum-safe (nist 1)",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "AES-256-GCM"},
			},
			wantQS:   types.QuantumSafe,
			wantNist: 1,
		},
		{
			name: "AES-ECB token → quantum-safe via base-token fallback",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "AES-ECB"},
			},
			wantQS:   types.QuantumSafe,
			wantNist: 1,
		},
		{
			name: "ML-KEM token → quantum-safe (nist 5)",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "ML-KEM"},
			},
			wantQS:   types.QuantumSafe,
			wantNist: 5,
		},
		{
			name: "RC4 token → broken",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "RC4"},
			},
			wantQS:   types.Broken,
			wantNist: 0,
		},
		{
			name: "no family / no primitive (jca-cipher-getinstance) stays blank",
			finding: types.Finding{
				AssetType: types.AssetAlgorithm,
				Pass:      2,
				RuleID:    "cbom-java-jca-cipher-getinstance",
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "unresolvable algorithm token (KECCAK-256) stays blank",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "KECCAK-256"},
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "PQC family absent from table (NTRU) stays blank",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "NTRU"},
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "certificate asset type stays blank (non-algorithm)",
			finding: types.Finding{
				AssetType:  types.AssetCertificate,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "RSA"},
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "related-crypto-material asset type stays blank (non-algorithm)",
			finding: types.Finding{
				AssetType:  types.AssetRelatedCryptoMaterial,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "RSA"},
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "library asset type stays blank (non-algorithm)",
			finding: types.Finding{
				AssetType:  "library",
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "AES"},
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "reroute marker (PRIVATE-KEY-PEM) stays blank — rerouted off algorithm axis",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "PRIVATE-KEY-PEM"},
			},
			wantQS:   "",
			wantNist: 0,
		},
		{
			name: "TLS reroute marker stays blank — rerouted to protocol",
			finding: types.Finding{
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "TLS-1.2"},
			},
			wantQS:   "",
			wantNist: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.finding
			annotateQuantum(&f)
			if f.Properties.QuantumStatus != tc.wantQS {
				t.Errorf("QuantumStatus = %q, want %q", f.Properties.QuantumStatus, tc.wantQS)
			}
			if f.Properties.NistQuantumLevel != tc.wantNist {
				t.Errorf("NistQuantumLevel = %d, want %d", f.Properties.NistQuantumLevel, tc.wantNist)
			}
		})
	}
}

// TestAnnotateQuantum_PreservesPass1 verifies that a finding already carrying a
// quantum posture (the Pass-1 AST-scanner path, which labels at emit time) is
// left completely untouched — zero regressions, no relabeling.
func TestAnnotateQuantum_PreservesPass1(t *testing.T) {
	// Deliberately "wrong" pre-set posture: if the annotator overwrote it, the
	// assertion below would catch the regression.
	f := types.Finding{
		AssetType: types.AssetAlgorithm,
		Pass:      1,
		Properties: types.CryptoProperties{
			AlgorithmFamily:  "elgamal", // would normally resolve to quantum-vulnerable
			QuantumStatus:    types.QuantumSafe,
			NistQuantumLevel: 3,
		},
	}
	annotateQuantum(&f)
	if f.Properties.QuantumStatus != types.QuantumSafe {
		t.Errorf("QuantumStatus = %q, want preserved quantum-safe", f.Properties.QuantumStatus)
	}
	if f.Properties.NistQuantumLevel != 3 {
		t.Errorf("NistQuantumLevel = %d, want preserved 3", f.Properties.NistQuantumLevel)
	}
}

// TestAnnotateQuantum_ConverterIntegration verifies the end-to-end path: a Pass-2
// finding run through ConvertScanResult emits a quantumStatus property and the
// NistQuantumSecurityLevel in algorithmProperties.
func TestAnnotateQuantum_ConverterIntegration(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			{
				ID:         "f-elgamal",
				Name:       "bc-elgamal",
				AssetType:  types.AssetAlgorithm,
				Pass:       2,
				Properties: types.CryptoProperties{AlgorithmPrimitive: "ELGAMAL"},
			},
		},
	}
	bom := ConvertScanResult(result)
	if len(bom.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(bom.Components))
	}
	c := bom.Components[0]
	var gotQS string
	for _, p := range c.Properties {
		if p.Name == "quantumStatus" {
			gotQS = p.Value
		}
	}
	if gotQS != string(types.QuantumVulnerable) {
		t.Errorf("quantumStatus property = %q, want %q", gotQS, types.QuantumVulnerable)
	}
}
