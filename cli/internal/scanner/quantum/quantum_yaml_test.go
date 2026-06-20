package quantum

import (
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestYAML_LoadsAtPackageInit(t *testing.T) {
	if len(table) < 70 {
		t.Errorf("table has %d entries, want >= 70 (per spec target ~80)", len(table))
	}
	for _, fam := range []string{"rsa", "aes", "md5", "sha-256", "ml-kem", "ml-dsa", "slh-dsa"} {
		if _, ok := table[fam]; !ok {
			t.Errorf("table missing critical family: %q", fam)
		}
	}
}

func TestYAML_AliasesResolveToCanonical(t *testing.T) {
	for _, tc := range []struct{ alias, canonical string }{
		{"kyber", "ml-kem"}, {"kyber-512", "ml-kem"},
		{"dilithium", "ml-dsa"}, {"sphincs+", "slh-dsa"},
		{"falcon", "fn-dsa"},
	} {
		info := GetInfo(tc.alias)
		canonInfo := GetInfo(tc.canonical)
		if info.Status != canonInfo.Status {
			t.Errorf("alias %q status = %q, canonical %q status = %q (should match)",
				tc.alias, info.Status, tc.canonical, canonInfo.Status)
		}
	}
}

func TestYAML_NonAlgorithmAssetTypeSkips(t *testing.T) {
	info := GetInfoForAsset("openssl", "library")
	if info.Status != types.QuantumNotApplicable {
		t.Errorf("Status = %q, want not-applicable for library asset type", info.Status)
	}
	info = GetInfoForAsset("server-cert", "certificate")
	if info.Status != types.QuantumNotApplicable {
		t.Errorf("Status = %q, want not-applicable for certificate", info.Status)
	}
}

func TestNormalizeFamily(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"RSA-2048", "rsa"}, {"aes-128-gcm", "aes"}, {"ECDSA-P256", "ecdsa"},
		{"sha-256", "sha-256"}, {"sha3-512", "sha3-512"},
		{"", ""}, {"NotAlgorithm123", "notalgorithm"},
	} {
		got := normalizeFamily(tc.in)
		if got != tc.out {
			t.Errorf("normalizeFamily(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestYAMLLastUpdatedComment(t *testing.T) {
	if !strings.Contains(string(quantumYAML), "# Last updated:") {
		t.Error("quantum-readiness.yml should carry a Last updated: comment")
	}
}

func TestPriority_HNDLModel(t *testing.T) {
	cases := []struct {
		status    types.QuantumStatus
		primitive string
		want      types.QuantumPriority
	}{
		{types.QuantumVulnerable, "pke", types.QuantumPriorityCritical},       // RSA-OAEP
		{types.QuantumVulnerable, "key-agree", types.QuantumPriorityCritical}, // ECDH
		{types.QuantumVulnerable, "kem", types.QuantumPriorityCritical},
		{types.QuantumVulnerable, "signature", types.QuantumPriorityHigh}, // ECDSA
		{types.QuantumVulnerable, "hash", types.QuantumPriorityMedium},
		{types.QuantumVulnerable, "", types.QuantumPriorityMedium},
		{types.Broken, "hash", types.QuantumPriorityCritical}, // MD5
		{types.Broken, "block-cipher", types.QuantumPriorityCritical},
		{types.QuantumSafe, "kem", types.QuantumPriorityNone}, // ML-KEM
		{types.QuantumSafe, "block-cipher", types.QuantumPriorityNone},
		{types.QuantumUnknown, "pke", ""},
		{types.QuantumNotApplicable, "pke", ""},
	}
	for _, tc := range cases {
		if got := Priority(tc.status, tc.primitive); got != tc.want {
			t.Errorf("Priority(%q, %q) = %q, want %q", tc.status, tc.primitive, got, tc.want)
		}
	}
}

func TestMigrationTarget_Populated(t *testing.T) {
	// Vulnerable families carry a structured migration target.
	for _, fam := range []string{"rsa", "ecdsa", "dh", "md5", "des"} {
		if got := GetInfo(fam).MigrationTarget; got == "" {
			t.Errorf("GetInfo(%q).MigrationTarget is empty, want non-empty", fam)
		}
	}
	// Quantum-safe families have no migration target.
	if got := GetInfo("ml-kem").MigrationTarget; got != "" {
		t.Errorf("GetInfo(ml-kem).MigrationTarget = %q, want empty", got)
	}
	// Aliases resolve to the same target.
	if GetInfo("rsa-oaep").MigrationTarget != GetInfo("rsa").MigrationTarget {
		t.Error("alias rsa-oaep should share rsa's migration target")
	}
}
