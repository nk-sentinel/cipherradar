package yararules

import (
	"regexp"
	"strings"
	"testing"
)

// ruleHeader matches the `rule <ident> {` line that opens a YARA rule.
// We don't write a full YARA grammar — we just want the rule names so
// we can assert each has a meta block with cbom_primitive. False
// positives from string literals containing "rule foo {" are accepted
// as a tradeoff for parser simplicity; the ruleset under
// scanner/yara-rules/ doesn't have such literals today and the guard
// test would surface a regression if one were added.
var ruleHeader = regexp.MustCompile(`(?m)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)

// metaCbomPrimitive matches `cbom_primitive = "..."` within a meta block.
// YARA-X is tolerant of any whitespace; the regex matches the conservative
// "key = "value"" form the in-tree ruleset uses.
var metaCbomPrimitive = regexp.MustCompile(`(?m)^\s*cbom_primitive\s*=\s*"([^"\n]+)"`)

// TestRuleset_AllRulesHaveCbomPrimitive walks every embedded .yar file
// and asserts that for each `rule <name> {` block there is a
// `cbom_primitive = "..."` line somewhere between that header and the
// matching close brace. Without cbom_primitive the parser
// canonicalization can't populate AlgorithmPrimitive on Pass-3
// findings, so the finding would land in the CBOM without an asset
// identity. Catching this at test time prevents shipped rules from
// silently degrading the output.
func TestRuleset_AllRulesHaveCbomPrimitive(t *testing.T) {
	files, err := RuleFiles()
	if err != nil {
		t.Fatalf("listing embedded rules: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("embedded ruleset is empty — go:embed pattern did not match any .yar files")
	}

	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			body, err := ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			rules := splitRules(string(body))
			if len(rules) == 0 {
				t.Errorf("no rules detected in %s — file should declare at least one `rule { ... }` block", name)
				return
			}
			for ruleName, body := range rules {
				if !metaCbomPrimitive.MatchString(body) {
					t.Errorf("rule %s in %s is missing meta.cbom_primitive — Pass 3 findings will have empty AlgorithmPrimitive",
						ruleName, name)
				}
			}
		})
	}
}

// TestRuleset_MinimumRuleCount asserts the starter ruleset still has
// the 15 rules ADR-039 calls for. If the count drops, either a file
// was deleted unintentionally or the embed pattern stopped matching.
func TestRuleset_MinimumRuleCount(t *testing.T) {
	files, err := RuleFiles()
	if err != nil {
		t.Fatalf("listing embedded rules: %v", err)
	}
	total := 0
	for _, name := range files {
		body, err := ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		total += len(splitRules(string(body)))
	}
	if total < 15 {
		t.Errorf("expected >= 15 rules in starter ruleset (ADR-039 baseline), found %d", total)
	}
}

// splitRules carves the file into a map of rule name -> rule body
// (the text between the header line and the matching close brace). It
// uses brace counting because YARA rule bodies are nested with `{ }`
// (meta:, strings:, condition: subblocks) and a regex-only approach
// would mis-match.
func splitRules(src string) map[string]string {
	rules := make(map[string]string)
	headers := ruleHeader.FindAllStringSubmatchIndex(src, -1)
	for _, h := range headers {
		name := src[h[2]:h[3]]
		openBrace := h[1] - 1 // last char of the match is `{`
		depth := 1
		end := openBrace + 1
		for end < len(src) && depth > 0 {
			switch src[end] {
			case '{':
				depth++
			case '}':
				depth--
			}
			end++
		}
		if depth != 0 {
			// Unbalanced — skip; the YARA-X compiler would reject this
			// at scan time. Test surfaces a different error in that case.
			continue
		}
		rules[name] = src[openBrace:end]
	}
	return rules
}

// TestSplitRules_SmokeTest verifies splitRules handles a known-good
// rule structure. Guards the guard test — if splitRules has a bug,
// TestRuleset_AllRulesHaveCbomPrimitive could pass vacuously.
func TestSplitRules_SmokeTest(t *testing.T) {
	src := `
rule foo {
  meta:
    description = "f"
  condition:
    true
}

rule bar {
  meta:
    cbom_primitive = "AES"
  strings:
    $a = "hello"
  condition:
    $a
}
`
	got := splitRules(src)
	if len(got) != 2 {
		t.Fatalf("expected 2 rules, got %d: %v", len(got), got)
	}
	if !strings.Contains(got["bar"], "cbom_primitive") {
		t.Errorf("bar rule body should contain cbom_primitive, got %q", got["bar"])
	}
	if strings.Contains(got["foo"], "cbom_primitive") {
		t.Errorf("foo rule body should not contain cbom_primitive, got %q", got["foo"])
	}
}
