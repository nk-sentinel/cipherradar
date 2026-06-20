package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildPurl(t *testing.T) {
	cases := []struct {
		p    Package
		want string
	}{
		{Package{Ecosystem: EcosystemNPM, Name: "node-forge", Version: "1.3.1"}, "pkg:npm/node-forge@1.3.1"},
		{Package{Ecosystem: EcosystemNPM, Name: "@scope/pkg", Version: "2.0.0"}, "pkg:npm/%40scope/pkg@2.0.0"},
		{Package{Ecosystem: EcosystemPyPI, Name: "Cryptography", Version: "41.0.0"}, "pkg:pypi/cryptography@41.0.0"},
		{Package{Ecosystem: EcosystemMaven, Name: "bcprov-jdk18on", Group: "org.bouncycastle", Version: "1.77"}, "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77"},
		{Package{Ecosystem: EcosystemNPM, Name: "node-forge"}, "pkg:npm/node-forge"}, // version-less
		{Package{Ecosystem: EcosystemNPM, Name: ""}, ""},
	}
	for _, tc := range cases {
		if got := BuildPurl(tc.p); got != tc.want {
			t.Errorf("BuildPurl(%+v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestParseNpmLock_V3(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root"},
	    "node_modules/node-forge": {"version": "1.3.1"},
	    "node_modules/a/node_modules/node-forge": {"version": "0.10.0"}
	  }
	}`)
	pkgs, err := parseNpmLock(path)
	if err != nil {
		t.Fatal(err)
	}
	var found *Package
	for i := range pkgs {
		if pkgs[i].Name == "node-forge" {
			found = &pkgs[i]
		}
	}
	if found == nil || found.Version != "1.3.1" {
		t.Fatalf("expected node-forge@1.3.1 (direct), got %+v", found)
	}
	if !found.Direct {
		t.Error("top-level node-forge should be marked Direct")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "requirements.txt", "cryptography==41.0.0\nrequests>=2.0\n# comment\npynacl==1.5.0\n")
	pkgs, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["cryptography"] != "41.0.0" {
		t.Errorf("cryptography = %q, want 41.0.0", got["cryptography"])
	}
	if _, ok := got["requests"]; ok {
		t.Error("ranged requests should be skipped (unresolved)")
	}
}

func TestParsePomXML_PropertyResolution(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "pom.xml", `<project>
	  <properties><bc.version>1.77</bc.version></properties>
	  <dependencies>
	    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>${bc.version}</version></dependency>
	    <dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>2.1</version></dependency>
	  </dependencies>
	</project>`)
	pkgs, err := parsePomXML(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Name] = p
	}
	if got["bcprov-jdk18on"].Version != "1.77" {
		t.Errorf("bcprov-jdk18on version = %q, want 1.77 (from ${bc.version})", got["bcprov-jdk18on"].Version)
	}
	if got["bcprov-jdk18on"].Group != "org.bouncycastle" {
		t.Errorf("group = %q, want org.bouncycastle", got["bcprov-jdk18on"].Group)
	}
}

func TestResolveLibrary_SnippetDisambiguationAndVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "cryptography==41.0.0\n")
	src := writeFile(t, dir, "app.py", "from cryptography.hazmat import primitives\n")
	ix, _ := Build(dir)

	// Coarse token with multiple python candidates; snippet picks cryptography,
	// manifest pins the version.
	p, ok := ResolveLibrary(ix, "pyca-cryptography-or-hashlib-or-pycryptodome-or-pynacl",
		"from cryptography.hazmat import primitives", src)
	if !ok {
		t.Fatal("expected resolution")
	}
	if p.Name != "cryptography" || p.Version != "41.0.0" {
		t.Errorf("got %+v, want cryptography@41.0.0", p)
	}
	if got := BuildPurl(p); got != "pkg:pypi/cryptography@41.0.0" {
		t.Errorf("purl = %q", got)
	}
}

func TestResolveLibrary_StdlibYieldsNoPurl(t *testing.T) {
	ix, _ := Build(t.TempDir())
	if _, ok := ResolveLibrary(ix, "hashlib", "import hashlib", "x.py"); ok {
		t.Error("stdlib hashlib should not resolve to a package")
	}
	if _, ok := ResolveLibrary(ix, "jca", "", "X.java"); ok {
		t.Error("jca (stdlib) should not resolve")
	}
}

func TestResolveLibrary_VersionlessFallback(t *testing.T) {
	ix, _ := Build(t.TempDir()) // no manifests
	p, ok := ResolveLibrary(ix, "node-forge", "const forge = require('node-forge')", "a.js")
	if !ok {
		t.Fatal("expected unambiguous node-forge to resolve without a version")
	}
	if p.Version != "" {
		t.Errorf("expected no version, got %q", p.Version)
	}
	if BuildPurl(p) != "pkg:npm/node-forge" {
		t.Errorf("purl = %q, want pkg:npm/node-forge", BuildPurl(p))
	}
}

func TestIndex_NearestAncestor(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "cryptography==1.0.0\n")
	writeFile(t, root, "svc/requirements.txt", "cryptography==2.0.0\n")
	deep := writeFile(t, root, "svc/app.py", "from cryptography import x\n")
	ix, _ := Build(root)

	p, ok := ix.Resolve(EcosystemPyPI, "cryptography", deep)
	if !ok {
		t.Fatal("expected resolution")
	}
	if p.Version != "2.0.0" {
		t.Errorf("nearest-ancestor version = %q, want 2.0.0 (svc/)", p.Version)
	}

	top := filepath.Join(root, "main.py")
	p2, _ := ix.Resolve(EcosystemPyPI, "cryptography", top)
	if p2.Version != "1.0.0" {
		t.Errorf("root version = %q, want 1.0.0", p2.Version)
	}
}
