// Package astrules loads external, replaceable Pass-1 (tree-sitter AST)
// detection tables. Only the DATA (token -> crypto semantics) is externalized;
// the tree-sitter query machinery stays in each language scanner. This gives
// Pass 1 the same "bring your own rules" story Pass 2 (--rules-dir) and Pass 3
// (--yara-rules-dir) already have. See docs/ast-rules-external-design.md.
//
// The built-in tables ship embedded via //go:embed (source of truth in
// scanner/ast-rules/, synced by `go generate`). A caller-provided directory
// (--ast-rules-dir / CRADAR_AST_RULES_DIR) replaces the embedded tables on a
// per-language basis: a dir replaces only the languages whose <lang>.yml it
// contains; undefined languages keep the embedded tables.
package astrules

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:generate sh -c "cp ../../../../scanner/ast-rules/*.yml data/"

//go:embed data/*.yml
var embeddedFS embed.FS

// SupportedLanguages lists the languages that currently have an externalizable
// ast-rules file. Phase A ships Java; Phase B extends this set.
func SupportedLanguages() []string { return []string{"java"} }

// --- Row types (exported so language scanners can consume them) ---

// JCAClass is one JCA factory class -> detection info row.
type JCAClass struct {
	Class     string `yaml:"class"`
	Primitive string `yaml:"primitive"`
	RuleTag   string `yaml:"rule_tag"`
}

// AlgorithmFamily maps a JCA algorithm name (uppercased) to a quantum family.
type AlgorithmFamily struct {
	Name   string `yaml:"name"`
	Family string `yaml:"family"`
}

// BCEngine is a Bouncy Castle engine/signer class -> algorithm info row.
type BCEngine struct {
	Class     string `yaml:"class"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
}

// BCMode maps a Bouncy Castle mode class to a mode string.
type BCMode struct {
	Class string `yaml:"class"`
	Mode  string `yaml:"mode"`
}

// BCDigest is a Bouncy Castle digest class -> algorithm info row.
type BCDigest struct {
	Class  string `yaml:"class"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// SSLProtocol maps an SSLContext.getInstance() protocol string to info.
// Severity is one of: critical, high, medium, low, info.
type SSLProtocol struct {
	Protocol string `yaml:"protocol"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// JavaTables is the full set of Java Pass-1 detection tables.
type JavaTables struct {
	Version           int               `yaml:"version"`
	Language          string            `yaml:"language"`
	JCAClasses        []JCAClass        `yaml:"jca_classes"`
	AlgorithmFamilies []AlgorithmFamily `yaml:"algorithm_families"`
	BCEngines         []BCEngine        `yaml:"bc_engines"`
	BCAsymmetric      []BCEngine        `yaml:"bc_asymmetric"`
	BCModes           []BCMode          `yaml:"bc_modes"`
	BCDigests         []BCDigest        `yaml:"bc_digests"`
	SSLProtocols      []SSLProtocol     `yaml:"ssl_protocols"`
}

// readLangYAML returns the YAML bytes for lang. When dir is non-empty and
// dir/<lang>.yml exists, that external file is used (override); otherwise the
// embedded copy is returned (per-language fallback). The bool reports whether
// the source was external.
func readLangYAML(lang, dir string) ([]byte, bool, error) {
	if dir != "" {
		p := filepath.Join(dir, lang+".yml")
		b, err := os.ReadFile(p)
		if err == nil {
			return b, true, nil
		}
		if !os.IsNotExist(err) {
			return nil, false, fmt.Errorf("reading %s: %w", p, err)
		}
		// Absent — fall through to the embedded copy (per-language fallback).
	}
	b, err := embeddedFS.ReadFile("data/" + lang + ".yml")
	if err != nil {
		return nil, false, fmt.Errorf("no embedded ast-rules for language %q: %w", lang, err)
	}
	return b, false, nil
}

// LoadJava loads the Java tables from dir/java.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadJava(dir string) (*JavaTables, error) {
	b, _, err := readLangYAML("java", dir)
	if err != nil {
		return nil, err
	}
	var t JavaTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing java ast-rules: %w", err)
	}
	// A file that parses but defines none of the core tables is treated as
	// unusable, matching the Pass-2 "no loadable rules" contract.
	if len(t.JCAClasses) == 0 && len(t.AlgorithmFamilies) == 0 {
		return nil, fmt.Errorf("java ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadJavaEmbedded loads the embedded Java tables and panics on error. The
// embedded data is validated by tests, so a failure here is a build defect.
func MustLoadJavaEmbedded() *JavaTables {
	t, err := LoadJava("")
	if err != nil {
		panic("astrules: embedded java rules failed to load: " + err.Error())
	}
	return t
}

// ValidateRulesDir checks an explicitly provided --ast-rules-dir: it must
// contain at least one recognized <lang>.yml, and every recognized file that
// IS present must parse. Mirrors the Pass-2 --rules-dir "error if no loadable
// rules" contract. Undefined languages are not required (per-language fallback).
func ValidateRulesDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("empty rules directory")
	}
	found := 0
	for _, lang := range SupportedLanguages() {
		p := filepath.Join(dir, lang+".yml")
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("reading %s: %w", p, err)
		}
		found++
		switch lang {
		case "java":
			if _, err := LoadJava(dir); err != nil {
				return err
			}
		}
	}
	if found == 0 {
		return fmt.Errorf("no recognized <lang>.yml files (expected one of: %s)",
			strings.Join(SupportedLanguages(), ", "))
	}
	return nil
}
