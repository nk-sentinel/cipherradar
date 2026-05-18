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
				MaterialType: materialType,
			},
			Description: fmt.Sprintf("Hardcoded secret found in environment variable %q", keyName),
			RuleID:      "cbom-config-hardcoded-secret",
			Pass:        1,
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
					MaterialType: materialType,
				},
				Description: fmt.Sprintf("Hardcoded secret found in property %q", key),
				RuleID:      "cbom-config-hardcoded-secret",
				Pass:        1,
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

// isBoringValue returns true for obviously non-secret values.
func isBoringValue(v string) bool {
	lower := strings.ToLower(v)
	boring := []string{"true", "false", "yes", "no", "0", "1", "null", "none", ""}
	for _, b := range boring {
		if lower == b {
			return true
		}
	}
	return false
}

func nextID() string {
	n := findingCounter.Add(1)
	return fmt.Sprintf("CFG-%04d", n)
}
