package output

import (
	"strings"
	"testing"
)

func TestFormatFromPath_ExtensionMapping(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"unknown.xyz":            "",
		"cbom.json":              "cyclonedx-json",
		"Nested/Path/CBOM.JSON":  "cyclonedx-json",
		"report.cdx.json":        "cyclonedx-json",
		"report.cyclonedx.json":  "cyclonedx-json",
		"findings.sarif":         "sarif",
		"report.pdf":             "pdf",
		"summary.txt":            "text",
		"summary.text":           "text",
		"issues.sonar.json":      "sonarqube-generic",
		"nested/issues.SONAR.JSON": "sonarqube-generic",
	}
	for path, want := range cases {
		if got := FormatFromPath(path); got != want {
			t.Errorf("FormatFromPath(%q) = %q; want %q", path, got, want)
		}
	}
}

func TestFormatFromPath_SonarBeforeJSON(t *testing.T) {
	// The .sonar.json suffix must be matched before generic .json so
	// SonarQube reports are not mis-dispatched to the CycloneDX writer.
	if got := FormatFromPath("out.sonar.json"); got != "sonarqube-generic" {
		t.Fatalf(".sonar.json should win over .json: got %q", got)
	}
}

func TestResolveOutputFormat_Precedence(t *testing.T) {
	// 1. Explicit always wins.
	if got := ResolveOutputFormat("x.json", "sarif", "text", "cyclonedx-json"); got != "sarif" {
		t.Errorf("explicit should win: got %q", got)
	}
	// 2. Extension beats cfg and fallback when explicit is empty.
	if got := ResolveOutputFormat("x.sarif", "", "text", "cyclonedx-json"); got != "sarif" {
		t.Errorf("extension should beat cfg: got %q", got)
	}
	// 3. cfg beats fallback when explicit and extension are absent.
	if got := ResolveOutputFormat("", "", "text", "cyclonedx-json"); got != "text" {
		t.Errorf("cfg should beat fallback: got %q", got)
	}
	// 4. Fallback applies when nothing else is set.
	if got := ResolveOutputFormat("", "", "", "cyclonedx-json"); got != "cyclonedx-json" {
		t.Errorf("fallback: got %q", got)
	}
}

func TestValidateFormat(t *testing.T) {
	for _, ok := range SupportedFormats() {
		if err := ValidateFormat(ok); err != nil {
			t.Errorf("ValidateFormat(%q) unexpected error: %v", ok, err)
		}
	}
	err := ValidateFormat("bogus-format")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "bogus-format") {
		t.Errorf("error should name the offending format: %v", err)
	}
}
