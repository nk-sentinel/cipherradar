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
