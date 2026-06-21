package scanner

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestClassifyRule(t *testing.T) {
	tests := []struct {
		ruleID   string
		severity types.Severity
		want     types.Category
	}{
		// Warning tokens always win
		{"cbom-python-md5-as-password-hash", types.SeverityMedium, types.CategorySecurity},
		{"cbom-go-tls-disabled", types.SeverityInfo, types.CategorySecurity},
		{"cbom-php-mcrypt_encrypt-deprecated", types.SeverityHigh, types.CategorySecurity},
		{"cbom-python-ssl-cert-none", types.SeverityHigh, types.CategorySecurity},
		{"cbom-go-rsa-encryptpkcs1v15", types.SeverityHigh, types.CategorySecurity},
		{"cbom-cpp-aes-ecb", types.SeverityHigh, types.CategorySecurity},
		{"cbom-python-hashlib-low-iter", types.SeverityMedium, types.CategorySecurity},
		// Broken algorithm tokens
		{"cbom-python-hashlib-md5", types.SeverityInfo, types.CategorySecurity},
		{"cbom-go-sha1-sum", types.SeverityMedium, types.CategorySecurity},
		{"cbom-cpp-des", types.SeverityMedium, types.CategorySecurity},
		{"cbom-cpp-3des", types.SeverityMedium, types.CategorySecurity},
		{"cbom-regex-algo-rc4", types.SeverityMedium, types.CategorySecurity},
		{"cbom-regex-algo-sslv3", types.SeverityMedium, types.CategorySecurity},
		{"cbom-regex-algo-tlsv11", types.SeverityMedium, types.CategorySecurity},
		{"cbom-go-tls-10", types.SeverityMedium, types.CategorySecurity},
		// Inventory tokens
		{"cbom-python-cryptography-import", types.SeverityInfo, types.CategoryInventory},
		{"cbom-regex-pem-certificate-parse", types.SeverityInfo, types.CategoryInventory},
		{"cbom-rust-rustls-cipher-suite", types.SeverityInfo, types.CategoryInventory},
		{"cbom-java-jca-keysize", types.SeverityInfo, types.CategoryInventory},
		// Severity fallback
		{"cbom-python-cryptography-aes", types.SeverityInfo, types.CategoryInventory},
		{"cbom-go-rsa-generatekey", types.SeverityInfo, types.CategoryInventory},
		{"cbom-python-cryptography-hash-sha256", types.SeverityInfo, types.CategoryInventory},
		{"cbom-java-jca-secretkeyspec-aes", types.SeverityInfo, types.CategoryInventory},
		{"cbom-regex-algo-sha-256", types.SeverityInfo, types.CategoryInventory},
		// Medium+ defaults to security
		{"cbom-python-some-warning", types.SeverityHigh, types.CategorySecurity},
		{"cbom-regex-pem-rsa-private", types.SeverityHigh, types.CategoryInventory}, // -pem- inventory token wins
	}

	for _, tc := range tests {
		t.Run(tc.ruleID, func(t *testing.T) {
			got, mat := ClassifyRule(tc.ruleID, tc.severity)
			if got != tc.want {
				t.Errorf("ClassifyRule(%q, %q) Category = %q, want %q",
					tc.ruleID, tc.severity, got, tc.want)
			}
			if mat != types.MaturityStable {
				t.Errorf("ClassifyRule(%q, %q) Maturity = %q, want %q",
					tc.ruleID, tc.severity, mat, types.MaturityStable)
			}
		})
	}
}

func TestAnnotateFindings_PreservesExplicit(t *testing.T) {
	findings := []types.Finding{
		// Already-tagged finding must not be overwritten.
		{
			RuleID:   "cbom-test-foo",
			Severity: types.SeverityHigh,
			Category: types.CategoryInventory,
			Maturity: types.MaturityExperimental,
		},
		// Empty finding must be classified by RuleID + Severity.
		{
			RuleID:   "cbom-python-hashlib-md5",
			Severity: types.SeverityMedium,
		},
		// Empty RuleID falls back to severity.
		{
			RuleID:   "",
			Severity: types.SeverityHigh,
		},
	}
	got := AnnotateFindings(findings)
	if got[0].Category != types.CategoryInventory || got[0].Maturity != types.MaturityExperimental {
		t.Errorf("explicit metadata overwritten: %+v", got[0])
	}
	if got[1].Category != types.CategorySecurity || got[1].Maturity != types.MaturityStable {
		t.Errorf("md5 finding not classified as security: %+v", got[1])
	}
	if got[2].Category != types.CategorySecurity {
		t.Errorf("severity fallback failed: %+v", got[2])
	}
	// All findings must also have DefaultEnabled=true and a non-empty
	// NoiseRisk after annotation — otherwise rulefilter.normalizeLifecycle
	// sees Maturity!="" and short-circuits, leaving DefaultEnabled at false
	// (the Go zero value), which drops the finding at the default_enabled
	// gate (Bug 4 root cause).
	for i, f := range got {
		if !f.DefaultEnabled {
			t.Errorf("finding[%d] %q: DefaultEnabled=false (would be dropped by rulefilter)", i, f.RuleID)
		}
		if f.NoiseRisk == "" {
			t.Errorf("finding[%d] %q: NoiseRisk is empty (rulefilter normalization skipped)", i, f.RuleID)
		}
	}
}
