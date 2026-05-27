package pdf

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestQuantumMigrationBacklog_Top5(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			mkFinding("RSA", types.QuantumVulnerable, "auth.go"),
			mkFinding("RSA", types.QuantumVulnerable, "tokens.go"),
			mkFinding("ECDSA", types.QuantumVulnerable, "jwt.go"),
			mkFinding("MD5", types.Broken, "legacy.go"),
			mkFinding("AES", types.QuantumSafe, "crypto.go"), // not in backlog
		},
	}
	backlog := buildMigrationBacklog(result, 5)
	if len(backlog) != 3 {
		t.Errorf("backlog len = %d, want 3 (RSA, ECDSA, MD5)", len(backlog))
	}
	if backlog[0].Algorithm != "RSA" || backlog[0].Count != 2 {
		t.Errorf("backlog[0] = %+v, want RSA count=2", backlog[0])
	}
}

func mkFinding(algo string, qs types.QuantumStatus, file string) types.Finding {
	return types.Finding{
		Name: algo, AssetType: types.AssetAlgorithm,
		Properties: types.CryptoProperties{
			AlgorithmFamily: algo, QuantumStatus: qs,
		},
		Location: types.Location{File: file, StartLine: 1},
	}
}
