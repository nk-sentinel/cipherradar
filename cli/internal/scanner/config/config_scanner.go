// Package config provides a scanner for configuration files (.env, .properties)
// that detects hardcoded secrets and crypto-related configuration values.
package config

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

// ConfigScanner detects hardcoded secrets and crypto configuration in .env and .properties files.
type ConfigScanner struct {
	secretKeyRe  *regexp.Regexp
	algoValueRe  *regexp.Regexp
	tlsVersionRe *regexp.Regexp
}

// New creates a new ConfigScanner with all patterns precompiled.
func New() *ConfigScanner {
	return &ConfigScanner{
		// Matches key names that typically hold secrets.
		secretKeyRe: regexp.MustCompile(`(?i)^([^#\s][^=]*?(secret|key|password|token|api_key|apikey|auth|credential|private)[^=]*)=(.+)$`),
		// Matches algorithm names appearing in values.
		algoValueRe: regexp.MustCompile(`(?i)\b(AES|RSA|MD5|SHA|DES|3DES|RC4|Blowfish)\b`),
		// Matches TLS/SSL version references in values.
		tlsVersionRe: regexp.MustCompile(`(?i)\b(TLSv1\.?[012]?|SSLv[23])\b`),
	}
}

// Name returns the scanner name.
func (s *ConfigScanner) Name() string {
	return "config"
}

// Extensions returns the file extensions this scanner handles.
func (s *ConfigScanner) Extensions() []string {
	return []string{".env", ".properties"}
}

// ScanFile scans a configuration file for hardcoded secrets and crypto references.
func (s *ConfigScanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}

	var findings []types.Finding

	lines := bytes.Split(content, []byte("\n"))

	if strings.HasSuffix(path, ".env") {
		findings = append(findings, s.scanEnvFile(path, lines)...)
	} else if strings.HasSuffix(path, ".properties") {
		findings = append(findings, s.scanPropertiesFile(path, lines)...)
	}

	return scanner.AnnotateFindings(findings), nil
}

func (s *ConfigScanner) scanEnvFile(path string, lines [][]byte) []types.Finding {
	var findings []types.Finding

	for lineIdx, line := range lines {
		lineStr := string(line)
		trimmed := strings.TrimSpace(lineStr)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := s.secretKeyRe.FindStringSubmatch(trimmed)
		if matches == nil {
			continue
		}

		keyName := strings.TrimSpace(matches[1])
		value := strings.TrimSpace(matches[3])

		// Skip empty values
		if value == "" {
			continue
		}

		// Skip obviously non-secret values
		if isBoringValue(value) {
			continue
		}

		materialType := "password"
		if strings.Contains(strings.ToLower(keyName), "key") {
			materialType = "secret-key"
		} else if strings.Contains(strings.ToLower(keyName), "token") {
			materialType = "token"
		} else if strings.Contains(strings.ToLower(keyName), "credential") {
			materialType = "credential"
		}

		findings = append(findings, types.Finding{
			ID:        nextID(),
			AssetType: types.AssetRelatedCryptoMaterial,
			Name:      fmt.Sprintf("Hardcoded secret: %s", keyName),
			Location: types.Location{
				File:      path,
				StartLine: lineIdx + 1,
				StartCol:  1,
				EndLine:   lineIdx + 1,
				EndCol:    len(trimmed),
				Snippet:   trimmed,
			},
			Severity:   types.SeverityHigh,
			Confidence: types.ConfidenceMedium,
			Properties: types.CryptoProperties{
				MaterialType:       materialType,
				AlgorithmPrimitive: "HARDCODED-SECRET",
			},
			Description: fmt.Sprintf("Hardcoded secret found in environment variable %q", keyName),
			RuleID:      "cbom-config-hardcoded-secret",
			Pass:        1,
			// Hardcoded secrets are an inventory finding (asset discovery).
			// The security-warning angle is implicit in the rule name; we want
			// these to appear in --only-inventory output, not be filtered out.
			Category:       types.CategoryInventory,
			Maturity:       types.MaturityStable,
			NoiseRisk:      types.NoiseRiskLow,
			DefaultEnabled: true,
		})
	}

	return findings
}

func (s *ConfigScanner) scanPropertiesFile(path string, lines [][]byte) []types.Finding {
	var findings []types.Finding

	for lineIdx, line := range lines {
		lineStr := string(line)
		trimmed := strings.TrimSpace(lineStr)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}

		// Split on first = or :
		eqIdx := strings.IndexAny(trimmed, "=:")
		if eqIdx < 0 {
			continue
		}

		key := strings.TrimSpace(trimmed[:eqIdx])
		value := strings.TrimSpace(trimmed[eqIdx+1:])
		keyLower := strings.ToLower(key)

		// Check for password/secret keys
		if containsSecretIndicator(keyLower) && value != "" && !isBoringValue(value) {
			materialType := "password"
			if strings.Contains(keyLower, "key") {
				materialType = "secret-key"
			} else if strings.Contains(keyLower, "secret") {
				materialType = "password"
			} else if strings.Contains(keyLower, "token") {
				materialType = "token"
			}

			findings = append(findings, types.Finding{
				ID:        nextID(),
				AssetType: types.AssetRelatedCryptoMaterial,
				Name:      fmt.Sprintf("Hardcoded secret: %s", key),
				Location: types.Location{
					File:      path,
					StartLine: lineIdx + 1,
					StartCol:  1,
					EndLine:   lineIdx + 1,
					EndCol:    len(trimmed),
					Snippet:   trimmed,
				},
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					MaterialType:       materialType,
					AlgorithmPrimitive: "HARDCODED-SECRET",
				},
				Description: fmt.Sprintf("Hardcoded secret found in property %q", key),
				RuleID:      "cbom-config-hardcoded-secret",
				Pass:        1,
				// Hardcoded secrets are an inventory finding (asset discovery).
				// See scanEnvFile for rationale.
				Category:       types.CategoryInventory,
				Maturity:       types.MaturityStable,
				NoiseRisk:      types.NoiseRiskLow,
				DefaultEnabled: true,
			})
		}

		// Check for TLS/SSL version in values
		if tlsMatch := s.tlsVersionRe.FindString(value); tlsMatch != "" {
			findings = append(findings, types.Finding{
				ID:        nextID(),
				AssetType: types.AssetProtocol,
				Name:      fmt.Sprintf("TLS/SSL version: %s", tlsMatch),
				Location: types.Location{
					File:      path,
					StartLine: lineIdx + 1,
					StartCol:  eqIdx + 2,
					EndLine:   lineIdx + 1,
					EndCol:    len(trimmed),
					Snippet:   trimmed,
				},
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					ProtocolType:    "tls",
					ProtocolVersion: tlsMatch,
				},
				Description: fmt.Sprintf("TLS/SSL version %q configured in property %q", tlsMatch, key),
				RuleID:      "cbom-config-tls-version",
				Pass:        1,
			})
		}

		// Check for algorithm references in values (only if key doesn't already match secret)
		if !containsSecretIndicator(keyLower) {
			if algoMatch := s.algoValueRe.FindString(value); algoMatch != "" {
				findings = append(findings, types.Finding{
					ID:        nextID(),
					AssetType: types.AssetAlgorithm,
					Name:      fmt.Sprintf("Algorithm reference: %s", algoMatch),
					Location: types.Location{
						File:      path,
						StartLine: lineIdx + 1,
						StartCol:  eqIdx + 2,
						EndLine:   lineIdx + 1,
						EndCol:    len(trimmed),
						Snippet:   trimmed,
					},
					Severity:   types.SeverityInfo,
					Confidence: types.ConfidenceMedium,
					Properties: types.CryptoProperties{
						AlgorithmFamily: strings.ToLower(algoMatch),
					},
					Description: fmt.Sprintf("Algorithm %q referenced in property %q", algoMatch, key),
					RuleID:      "cbom-config-algorithm-ref",
					Pass:        1,
				})
			}
		}
	}

	return findings
}

// containsSecretIndicator returns true if the key name contains a secret-related word.
func containsSecretIndicator(keyLower string) bool {
	indicators := []string{"secret", "key", "password", "token", "auth", "credential", "private"}
	for _, ind := range indicators {
		if strings.Contains(keyLower, ind) {
			return true
		}
	}
	return false
}

// isBoringValue returns true for obviously non-secret values. We use it to
// suppress hardcoded-secret findings on:
//   - boolean / null / numeric flags
//   - template placeholders (`<your_secret>`, `${VAR}`, `{{var}}`, `%VAR%`)
//   - obvious placeholder strings (`changeme`, `placeholder`, `xxx`, `***`,
//     `your_*_here`)
//   - quoted-empty values (`""`, `''`)
//   - very short non-templated values (< 4 chars) that are almost never real
//     secrets and frequently false-positive on things like `key=1` flags
//
// The goal is to keep --only-inventory clean enough that an operator skimming
// it can trust every line as a real asset.
func isBoringValue(v string) bool {
	if v == "" {
		return true
	}
	// Strip matching surrounding quotes once so `""` and `"secret"` are
	// both inspected on their core value.
	stripped := v
	if len(stripped) >= 2 {
		first, last := stripped[0], stripped[len(stripped)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			stripped = stripped[1 : len(stripped)-1]
		}
	}
	if stripped == "" {
		return true
	}
	lower := strings.ToLower(stripped)

	// Boolean / null / single-digit flag values.
	flagLiterals := map[string]bool{
		"true": true, "false": true, "yes": true, "no": true,
		"0": true, "1": true, "null": true, "none": true, "nil": true,
	}
	if flagLiterals[lower] {
		return true
	}

	// Template / env-var placeholders. Catches `${VAR}`, `{{var}}`, `%VAR%`,
	// `<your_secret>`, `[REDACTED]`, etc. — anything wrapped in matched
	// brackets/braces that obviously isn't a literal secret.
	if isTemplatePlaceholder(stripped) {
		return true
	}

	// Common placeholder words. We check the whole value (not substring) so
	// "changeme" matches but "ifChangemeQ7..." does not — long values with
	// these words embedded are likely real.
	placeholders := []string{
		"changeme", "change_me", "change-me",
		"placeholder", "todo", "tbd", "fixme",
		"xxx", "xxxx", "xxxxx",
		"secret", "password", "secretkey", "apikey", "token",
		"example", "sample", "test", "dummy", "fake",
		"foo", "bar", "baz",
		"***", "****", "*****",
		"redacted",
	}
	for _, p := range placeholders {
		if lower == p {
			return true
		}
	}
	// "your_*_here" pattern (e.g. `your_api_key_here`, `your-secret-here`).
	if strings.HasPrefix(lower, "your_") || strings.HasPrefix(lower, "your-") {
		if strings.HasSuffix(lower, "_here") || strings.HasSuffix(lower, "-here") {
			return true
		}
	}

	// Very short values are almost never real high-entropy secrets and
	// frequently fire on accidental matches like `key=1` or `key=on`.
	if len(stripped) < 4 {
		return true
	}

	return false
}

// isTemplatePlaceholder returns true if v looks like an unfilled template
// placeholder rather than a literal secret. Heuristics:
//   - `${...}`, `{{...}}`, `%...%`, `<...>`, `[...]` — the whole value is
//     wrapped in a matched pair of these delimiters
func isTemplatePlaceholder(v string) bool {
	n := len(v)
	if n < 2 {
		return false
	}
	pairs := []struct{ open, close string }{
		{"${", "}"},
		{"{{", "}}"},
		{"%", "%"},
		{"<", ">"},
		{"[", "]"},
		{"{", "}"},
	}
	for _, p := range pairs {
		if strings.HasPrefix(v, p.open) && strings.HasSuffix(v, p.close) {
			// Avoid matching `%` against single-char `%` or empty inside.
			if n > len(p.open)+len(p.close) {
				return true
			}
		}
	}
	return false
}

func nextID() string {
	n := findingCounter.Add(1)
	return fmt.Sprintf("CFG-%04d", n)
}
