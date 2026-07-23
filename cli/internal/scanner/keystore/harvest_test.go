package keystore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeF(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHarvestPasswords_ConfigAndSource(t *testing.T) {
	dir := t.TempDir()
	// A keystore must be present for harvesting to run at all.
	writeF(t, dir, "certs/app.jks", "")
	writeF(t, dir, "src/main/resources/application.properties",
		"server.ssl.key-store-password=propPass\nserver.port=8080\n")
	writeF(t, dir, "src/main/resources/application.yml",
		"server:\n  ssl:\n    key-store-password: yamlPass\n")
	writeF(t, dir, ".env", "KEYSTORE_PASSWORD=envPass\nOTHER=nope\n")
	writeF(t, dir, "conf/server.xml",
		`<Connector keystoreFile="a.jks" keystorePass="tomcatPass" />`)
	writeF(t, dir, "src/App.java", `void f(){ ks.load(in, "javaPass".toCharArray()); }`)
	// Values that must be filtered out:
	writeF(t, dir, "bad.properties",
		"key-store-password=${env.KS_PASS}\ntrust-store-password=/etc/ssl/store.jks\n")

	got := HarvestPasswords(dir)
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, want := range []string{"propPass", "yamlPass", "envPass", "tomcatPass", "javaPass"} {
		if !set[want] {
			t.Errorf("expected harvested password %q, got %v", want, got)
		}
	}
	if set["${env.KS_PASS}"] || set["/etc/ssl/store.jks"] {
		t.Errorf("filtered values leaked into harvest: %v", got)
	}
}

func TestHarvestPasswords_NoKeystoreReturnsNil(t *testing.T) {
	dir := t.TempDir()
	writeF(t, dir, "application.properties", "server.ssl.key-store-password=abc\n")
	if got := HarvestPasswords(dir); got != nil {
		t.Errorf("no keystore in tree -> expected nil, got %v", got)
	}
}

func TestHarvestPasswords_CapAndDedup(t *testing.T) {
	dir := t.TempDir()
	writeF(t, dir, "a.jks", "")
	var sb strings.Builder
	// Same value repeated (dedup) + many distinct (cap).
	sb.WriteString("key-store-password=dup\nkey-store-password=dup\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&sb, "key-store-password=pw%d\n", i)
	}
	writeF(t, dir, "many.properties", sb.String())
	got := HarvestPasswords(dir)
	if len(got) > maxHarvested {
		t.Errorf("harvested %d, want <= %d (cap)", len(got), maxHarvested)
	}
	dupCount := 0
	for _, g := range got {
		if g == "dup" {
			dupCount++
		}
	}
	if dupCount > 1 {
		t.Errorf("expected 'dup' deduped, appeared %d times", dupCount)
	}
}

func TestHarvestCandidateOrdering(t *testing.T) {
	defer SetHarvestedPasswords(nil) // reset package state
	SetHarvestedPasswords([]string{"harvestedXYZ"})
	cands := passwordCandidates("app.jks")
	defaultIdx, harvestIdx := -1, -1
	for i, c := range cands {
		switch c {
		case "changeit":
			defaultIdx = i
		case "harvestedXYZ":
			harvestIdx = i
		}
	}
	if defaultIdx == -1 || harvestIdx == -1 || defaultIdx > harvestIdx {
		t.Errorf("defaults must precede harvested (lazy escalation): changeit@%d harvested@%d",
			defaultIdx, harvestIdx)
	}
}

func TestPlausiblePassword(t *testing.T) {
	bad := []string{
		"", "${x}", "#{x}", "%(x)", "https://host/x", "/etc/x", "./rel",
		"null", "true", "store.jks", "trust.p12", strings.Repeat("a", 200),
	}
	for _, b := range bad {
		if plausiblePassword(b) {
			t.Errorf("plausiblePassword(%q) = true, want false", b)
		}
	}
	good := []string{"changeit", "s3cr3t!", "P@ssw0rd", "abc123", "keystorepass"}
	for _, g := range good {
		if !plausiblePassword(g) {
			t.Errorf("plausiblePassword(%q) = false, want true", g)
		}
	}
}
