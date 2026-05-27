package pdf

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestAggregate_CountsByDimension(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			{ID: "1", Name: "AES", AssetType: types.AssetAlgorithm,
				Severity: types.SeverityMedium,
				Properties: types.CryptoProperties{
					AlgorithmFamily: "AES", Primitive: "block-cipher", QuantumStatus: types.QuantumSafe,
				},
				Location: types.Location{File: "a.py"}},
			{ID: "2", Name: "AES", AssetType: types.AssetAlgorithm,
				Severity: types.SeverityMedium,
				Properties: types.CryptoProperties{
					AlgorithmFamily: "AES", Primitive: "block-cipher", QuantumStatus: types.QuantumSafe,
				},
				Location: types.Location{File: "b.py"}},
			{ID: "3", Name: "RSA", AssetType: types.AssetAlgorithm,
				Severity: types.SeverityHigh,
				Properties: types.CryptoProperties{
					AlgorithmFamily: "RSA", Primitive: "signature", QuantumStatus: types.QuantumVulnerable,
				},
				Location: types.Location{File: "auth.go"}},
			{ID: "4", Name: "openssl", AssetType: types.AssetType("library"),
				Properties: types.CryptoProperties{QuantumStatus: types.QuantumNotApplicable},
				Location:   types.Location{File: "requirements.txt"}},
		},
	}
	s := Aggregate(result)
	if s.AssetType["algorithm"] != 3 {
		t.Errorf("AssetType[algorithm] = %d, want 3", s.AssetType["algorithm"])
	}
	if s.AssetType["library"] != 1 {
		t.Errorf("AssetType[library] = %d, want 1", s.AssetType["library"])
	}
	if s.Primitive["block-cipher"] != 2 {
		t.Errorf("Primitive[block-cipher] = %d, want 2", s.Primitive["block-cipher"])
	}
	if s.Quantum[types.QuantumNotApplicable] != 0 {
		t.Error("Quantum should not count NotApplicable in the breakdown")
	}
	if len(s.TopAlgorithms) == 0 || s.TopAlgorithms[0].Key != "AES" || s.TopAlgorithms[0].Value != 2 {
		t.Errorf("TopAlgorithms[0] = %+v, want AES=2 first", s.TopAlgorithms[0])
	}
	if s.Files != 4 {
		t.Errorf("Files = %d, want 4 (unique paths)", s.Files)
	}
	// Language is derived from file extension; .py → "python", .go → "go", .txt → ""
	if s.Language["python"] != 2 {
		t.Errorf("Language[python] = %d, want 2", s.Language["python"])
	}
	if s.Language["go"] != 1 {
		t.Errorf("Language[go] = %d, want 1", s.Language["go"])
	}
	// requirements.txt has no recognized extension mapping → not counted
	if s.Languages != 2 {
		t.Errorf("Languages = %d, want 2 (python + go)", s.Languages)
	}
}
