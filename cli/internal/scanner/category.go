package scanner

import (
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ClassifyRule infers a (Category, Maturity) tuple for a Pass-1 AST scanner
// finding based on its RuleID and Severity. It is the single source of truth
// for Pass-1 categorization so that --only-inventory / --only-security filters
// return useful subsets rather than dropping everything (Bug 4 fix).
//
// Heuristics, in priority order:
//
//  1. Explicit warning tokens in the rule name → CategorySecurity.
//     Includes: weak, broken, insecure, hardcoded, disabled, deprecated,
//     ecb, pkcs1v15, no-padding, low-iter, low-entropy, expired,
//     self-signed, cert-none, no-verify, padding-oracle, downgrade,
//     anonymous, null-cipher, export-cipher.
//
//  2. Explicit broken/deprecated algorithm tokens → CategorySecurity.
//     Includes: md5, sha-1/sha1, des (not 3des-derived suffix), rc4,
//     3des, tripledes, sslv3, sslv2, tlsv10, tlsv11, dsa, md4, md2,
//     mcrypt, blowfish-as-primary.
//
//  3. Pure asset-discovery tokens → CategoryInventory.
//     Includes: -import, -found, -asset, -detect, -library, -package,
//     -pem-, -cipher-suite, -keysize, -curve, -protocol (when not a
//     deprecated version).
//
//  4. Severity-based fallback.
//     SeverityCritical / SeverityHigh → CategorySecurity.
//     SeverityMedium → CategorySecurity (errs on the safe side; a Medium
//     rule generally signals an actionable concern, e.g. PBKDF2 with low
//     iterations, expiring-soon certificates).
//     SeverityLow / SeverityInfo → CategoryInventory.
//
// Maturity defaults to MaturityStable for every Pass-1 finding — this matches
// the YAML-rule default behavior in internal/opengrep/parser.go.
func ClassifyRule(ruleID string, severity types.Severity) (types.Category, types.Maturity) {
	id := strings.ToLower(ruleID)

	// 1) Explicit warning tokens — these are always security regardless of severity.
	securityTokens := []string{
		"-weak",
		"-broken",
		"-insecure",
		"-hardcoded",
		"-disabled",
		"-deprecated",
		"-ecb",
		"-pkcs1v15",
		"-no-padding",
		"-nopadding",
		"-low-iter",
		"-low-entropy",
		"-expired",
		"-self-signed",
		"-cert-none",
		"-no-verify",
		"-noverify",
		"-padding-oracle",
		"-downgrade",
		"-anonymous",
		"-null-cipher",
		"-export-cipher",
		"-static-iv",
		"-zero-iv",
		"-fixed-iv",
		"-reused-",
		"-cbc-without-mac",
		"-mac-then-encrypt",
		"-as-password",
	}
	for _, tok := range securityTokens {
		if strings.Contains(id, tok) {
			return types.CategorySecurity, types.MaturityStable
		}
	}

	// 2) Explicit broken/deprecated algorithm tokens.
	// Order matters: check more-specific tokens before generic ones to avoid
	// false matches (e.g. "3des" before "des", "sha-256" before "sha-").
	brokenAlgoTokens := []string{
		"-md5",
		"-md4",
		"-md2",
		"-sha-1",
		"-sha1",
		"-rc4",
		"-rc2",
		"-3des",
		"-tripledes",
		"-sslv3",
		"-sslv2",
		"-tlsv10",
		"-tlsv11",
		"-tls-10",
		"-tls-11",
		"-mcrypt",
	}
	// Avoid misclassifying "-sha-256", "-sha256", "-3des-cbc-detect" style IDs
	// when a non-broken qualifier follows. We only treat the token as broken
	// when it sits at a word boundary in the rule name.
	for _, tok := range brokenAlgoTokens {
		if hasBoundaryToken(id, tok) {
			return types.CategorySecurity, types.MaturityStable
		}
	}
	// "des" without "3des"/"triple-des" prefix.
	if hasBoundaryToken(id, "-des") &&
		!strings.Contains(id, "-3des") &&
		!strings.Contains(id, "-tripledes") {
		return types.CategorySecurity, types.MaturityStable
	}

	// 3) Pure asset-discovery tokens → inventory.
	inventoryTokens := []string{
		"-import",
		"-imports",
		"-found",
		"-asset",
		"-detect",
		"-library",
		"-package",
		"-pem-",
		"-cipher-suite",
		"-keysize",
		"-curve",
		"-certificate-parsed",
	}
	for _, tok := range inventoryTokens {
		if strings.Contains(id, tok) {
			return types.CategoryInventory, types.MaturityStable
		}
	}

	// 4) Severity-based fallback.
	switch severity {
	case types.SeverityCritical, types.SeverityHigh, types.SeverityMedium:
		return types.CategorySecurity, types.MaturityStable
	default:
		return types.CategoryInventory, types.MaturityStable
	}
}

// hasBoundaryToken reports whether id contains tok at a hyphen or end-of-string
// word boundary. It prevents "-sha-1" matching "-sha-128" or "-des" matching
// "-tripledes-derived".
func hasBoundaryToken(id, tok string) bool {
	for {
		idx := strings.Index(id, tok)
		if idx < 0 {
			return false
		}
		end := idx + len(tok)
		if end == len(id) || id[end] == '-' {
			return true
		}
		id = id[end:]
	}
}

// noiseGatedOffByDefault lists Pass-1 rule IDs that are nominally inventory
// but so noisy — loose entropy matches that mint a CBOM related-crypto-material
// component typed literally "unknown" — that they ship OFF by default and are
// gated behind --include-noisy. Setting BOTH NoiseRiskHigh and
// DefaultEnabled=false is the canonical pattern the rulefilter re-enables via
// --include-noisy (see rulefilter.isDefaultKeep); --include-rule / --rules also
// bring them back. (WS2; also reduces the k8s cert double-count in issue #70,
// with a complementary shape-suppression in the regex scanner.)
var noiseGatedOffByDefault = map[string]bool{
	"cbom-regex-hex-key":    true,
	"cbom-regex-base64-key": true,
}

// AnnotateFindings fills empty lifecycle metadata (Category, Maturity,
// NoiseRisk, DefaultEnabled) on every finding via ClassifyRule. Pass-1 AST
// scanners call this as the last step of ScanFile so that all emitted
// findings carry lifecycle metadata. Findings that already have a field
// set (e.g. seeded from a typed pattern table) are left untouched per-field.
//
// IMPORTANT: rulefilter.normalizeLifecycle uses Maturity != "" as the
// "this finding already has lifecycle metadata, trust all fields" signal.
// As soon as we set Maturity here, the rulefilter stops auto-defaulting
// DefaultEnabled to true — so this function MUST also set DefaultEnabled
// (and NoiseRiskLow) or Pass-1 findings get silently dropped at the
// default_enabled gate (Bug 4 root cause).
func AnnotateFindings(findings []types.Finding) []types.Finding {
	for i := range findings {
		// Noise-gated rules override the default "Pass-1 runs by default"
		// policy: force them off by default + noise_risk:high so a normal
		// scan is quiet and --include-noisy brings them back.
		if noiseGatedOffByDefault[findings[i].RuleID] {
			if findings[i].Category == "" {
				findings[i].Category = types.CategoryInventory
			}
			if findings[i].Maturity == "" {
				findings[i].Maturity = types.MaturityStable
			}
			findings[i].NoiseRisk = types.NoiseRiskHigh
			findings[i].DefaultEnabled = false
			continue
		}

		hasCat := findings[i].Category != ""
		hasMat := findings[i].Maturity != ""
		if hasCat && hasMat {
			// Even if Category+Maturity are pre-set (e.g. typed regex patterns),
			// fill in default_enabled/noise_risk so the rulefilter treats them
			// as opted-in. Without this, regex-scanner pem patterns get dropped
			// at the default_enabled gate when they pre-set Category/Maturity.
			if findings[i].NoiseRisk == "" {
				findings[i].NoiseRisk = types.NoiseRiskLow
			}
			if !findings[i].DefaultEnabled {
				findings[i].DefaultEnabled = true
			}
			continue
		}
		cat, mat := ClassifyRule(findings[i].RuleID, findings[i].Severity)
		if !hasCat {
			findings[i].Category = cat
		}
		if !hasMat {
			findings[i].Maturity = mat
		}
		if findings[i].NoiseRisk == "" {
			findings[i].NoiseRisk = types.NoiseRiskLow
		}
		// Pre-lifecycle Pass-1 findings ran by default — keep them flowing.
		findings[i].DefaultEnabled = true
	}
	return findings
}
